//! Per-process GPU memory on Windows, where `nvidia-smi` cannot say.
//!
//! Under Windows' WDDM driver model `--query-compute-apps` reports `[N/A]` for every process's
//! memory, so `read_card_occupancy` cannot credit our own warm worker with what it holds, and the
//! VRAM gate has no opinion on any card one of our workers is on. Windows itself accounts each
//! process's video memory, in the `GPU Process Memory` performance counters Task Manager shows:
//! one instance per process and adapter, `pid_<pid>_luid_<luid>_phys_<n>`, whose `Dedicated
//! Usage` is the device memory that process holds there.
//!
//! Only the card being read counts: a process holds memory on each adapter it uses (our SP1 worker
//! keeps every card visible to CUDA, so it can hold a context on a card it does not prove on), and
//! crediting it with its total on each would read another card's memory as ours here, hiding
//! another program's and overstating what is free. The card is matched by PCI address to its
//! adapter LUID (`d3dkmt::adapters`), the id the counters name.

use std::collections::HashMap;
use std::ffi::c_void;

const MIB: u64 = 1024 * 1024;

/// An adapter LUID, as Windows' counters spell it: `luid_0x<high>_0x<low>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct AdapterLuid {
    pub high: u32,
    pub low: u32,
}

/// Fills in the memory `nvidia-smi` left unreported, from the counters, for the card at PCI address
/// `pci_bus_id` (normalized, `0000:03:00.0`) whose `nvidia-smi` `memory.used` is `used_mib`. A
/// process the counters list nothing for ON THIS CARD holds no device memory here.
///
/// When the card cannot be matched to an adapter (no PCI address, no single adapter at it, its
/// adapter's own figure far from `used_mib` even after resolving again) or the counters cannot be
/// read, the rows are returned as they were: one of ours left unreported makes the reading "no
/// opinion" (`apps_we_can_attribute`), the safe answer, where crediting a process with what it
/// holds on every card would not be.
pub(crate) fn fill_unreported(
    apps: Vec<(u32, Option<u64>)>,
    pci_bus_id: Option<&str>,
    used_mib: u64,
) -> Vec<(u32, Option<u64>)> {
    if apps.iter().all(|(_, mib)| mib.is_some()) {
        return apps;
    }
    let Some(held) = pci_bus_id.and_then(|pci| dedicated_mib_on_card(pci, used_mib)) else {
        return apps;
    };
    apps.into_iter()
        .map(|(pid, mib)| {
            (
                pid,
                mib.or_else(|| Some(held.get(&pid).copied().unwrap_or(0))),
            )
        })
        .collect()
}

/// Device memory each process holds on the card at `pci_bus_id`, in MiB: `None` when the card
/// cannot be matched to one adapter whose own figure agrees with `used_mib`, or the counters cannot
/// be read. A LUID can change (a driver reset), so a disagreement resolves once more before giving
/// up.
fn dedicated_mib_on_card(pci_bus_id: &str, used_mib: u64) -> Option<HashMap<u32, u64>> {
    for _ in 0..2 {
        let luid = d3dkmt::adapters().and_then(|a| luid_for_pci(&a, pci_bus_id))?;
        let processes = pdh::read_counter_array(r"\GPU Process Memory(*)\Dedicated Usage")?;
        let adapters = pdh::read_counter_array(r"\GPU Adapter Memory(*)\Dedicated Usage")?;
        let (by_pid, adapter_mib) = on_adapter(&processes, &adapters, luid);
        if adapter_mib.is_some_and(|a| agrees_with_smi(a, used_mib)) {
            return Some(by_pid);
        }
    }
    None
}

/// What a running proof's processes (`pids`) and every other process hold of a card, in MiB, from
/// one reading of Windows' counters (`proof_card_use`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofCardUse {
    /// Of `pids`' memory on the card, what Windows has moved off it.
    pub evicted_mib: u64,
    /// What every OTHER process has allocated on the card: other programs, and our other workers.
    pub others_mib: u64,
    /// Whether the card was full when read ([`card_is_full`]), `None` when its size or use could
    /// not be read.
    pub card_full: Option<bool>,
}

/// How close to its dedicated memory a card must be for memory read as moved off it to count
/// (`card_is_full`), in MiB: about what a WDDM process budget leaves below the card's size (768
/// MiB here), and a little more.
pub(crate) const CARD_FULL_WITHIN_MIB: u64 = 1024;

/// Whether a card of `total_bytes` dedicated memory, `resident_mib` of it in use right now (the
/// adapter's own `Dedicated Usage`), was full: within [`CARD_FULL_WITHIN_MIB`] of its size. `None`
/// when either is unknown.
///
/// Windows moves a process's memory off a card only to make room on it, so memory read as moved off
/// a card that is not full is no spill. A proof allocating or freeing a large block reads that way
/// for a moment (its `Dedicated Usage` moves before its `Local Usage`): an RX 9070 XT read up to
/// 1,648 MiB "evicted" for one sample at a time, with 2.5-13.5 GB of its 16 GB in use, in a 4-hour
/// soak where nothing was moved off the card and no proof slowed.
pub(crate) fn card_is_full(resident_mib: Option<u64>, total_bytes: Option<u64>) -> Option<bool> {
    let total_mib = total_bytes? / MIB;
    Some(resident_mib?.saturating_add(CARD_FULL_WITHIN_MIB) >= total_mib)
}

/// [`ProofCardUse`] for `pids` on the card at `pci_bus_id` (normalized, `0000:03:00.0`): `None`
/// when the card cannot be matched to one adapter or the counters cannot be read.
///
/// `evicted_mib` is the device memory of `pids` that Windows has moved off the card.
///
/// A process's `Dedicated Usage` is the device memory it has allocated, and its `Local Usage` the
/// part of it resident on the card right now. They are equal while it has the card to itself: an
/// SP1 proof at 2^28 on an RTX 4070 read 0 MiB apart in every sample, allocating included. When
/// another program's memory and ours no longer fit together, Windows does not fail either of them:
/// it pages them in turns, and our server read 9 MiB resident of 9,875 allocated for seconds at a
/// time while its proofs took 8-12 times as long. That gap is what this measures. Both counters are
/// read in one collection, so a block freed between two reads cannot look evicted.
///
/// `others_mib` is what the card's other processes have allocated there. A program that takes
/// memory without either of them being paged (it and ours fit together) still leaves ours less to
/// work with: a risc0 benchmark on an RTX 4070 ran at half speed beside 6 GB of another program's,
/// resident throughout. A measurement during which this grew is no measurement of the card.
///
/// `card_full` says whether the card was full at that reading ([`card_is_full`], from the adapter's
/// `Dedicated Usage`, read in the same collection, and its size from the kernel thunks), since
/// memory read as moved off a card that has room is a block on its way in or out, not a spill.
pub(crate) fn proof_card_use(pids: &[u32], pci_bus_id: &str) -> Option<ProofCardUse> {
    let luid = d3dkmt::adapters().and_then(|a| luid_for_pci(&a, pci_bus_id))?;
    let mut read = pdh::read_counter_arrays(&[
        r"\GPU Process Memory(*)\Dedicated Usage",
        r"\GPU Process Memory(*)\Local Usage",
        r"\GPU Adapter Memory(*)\Dedicated Usage",
    ])?;
    let adapters = read.pop()?;
    let local = read.pop()?;
    let dedicated = read.pop()?;
    let (_, resident_mib) = on_adapter(&[], &adapters, luid);
    Some(ProofCardUse {
        card_full: card_is_full(resident_mib, dedicated_bytes_cached(luid)),
        ..card_use(&dedicated, &local, luid, pids)
    })
}

/// One card's memory, in bytes, from one reading of Windows' counters ([`card_memory`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardMemory {
    /// The card's dedicated video memory, as the driver reports it.
    pub total: u64,
    /// What every process holds of it (the adapter's own `Dedicated Usage`).
    pub used: u64,
    /// What each process holds of it.
    pub by_pid: Vec<(u32, u64)>,
}

/// The memory of the card at `pci_bus_id` (normalized, `0000:03:00.0`), for a card `nvidia-smi`
/// does not read (AMD's): its size from the kernel thunks, what is in use and who holds it from the
/// counters, read in one collection. `None` when the card cannot be matched to one adapter or the
/// counters or its size cannot be read.
pub(crate) fn card_memory(pci_bus_id: &str) -> Option<CardMemory> {
    let luid = d3dkmt::adapters().and_then(|a| luid_for_pci(&a, pci_bus_id))?;
    let total = dedicated_bytes_cached(luid)?;
    let mut read = pdh::read_counter_arrays(&[
        r"\GPU Process Memory(*)\Dedicated Usage",
        r"\GPU Adapter Memory(*)\Dedicated Usage",
    ])?;
    let adapters = read.pop()?;
    let processes = read.pop()?;
    let (by_pid, used_mib) = on_adapter(&processes, &adapters, luid);
    Some(CardMemory {
        total,
        used: used_mib?.saturating_mul(MIB),
        by_pid: by_pid
            .into_iter()
            .map(|(pid, mib)| (pid, mib.saturating_mul(MIB)))
            .collect(),
    })
}

/// The dedicated video memory of adapter `luid` (`d3dkmt::dedicated_bytes`), asked of the driver
/// once per adapter and process: a card's size does not change, and the spill watch reads every 2 s
/// for each proof. An adapter that comes back after a driver reset has a new LUID, and is asked again.
fn dedicated_bytes_cached(luid: AdapterLuid) -> Option<u64> {
    static SIZES: std::sync::Mutex<Option<HashMap<AdapterLuid, u64>>> = std::sync::Mutex::new(None);
    let mut sizes = SIZES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(bytes) = sizes.as_ref().and_then(|m| m.get(&luid)) {
        return Some(*bytes);
    }
    let bytes = d3dkmt::dedicated_bytes(luid)?;
    sizes.get_or_insert_with(HashMap::new).insert(luid, bytes);
    Some(bytes)
}

/// [`ProofCardUse`] from one reading: `pids`' `dedicated` memory on `luid` that is not `local`
/// (resident), summed, and every other process's `dedicated` memory there.
fn card_use(
    dedicated: &[(String, u64)],
    local: &[(String, u64)],
    luid: AdapterLuid,
    pids: &[u32],
) -> ProofCardUse {
    let (dedicated, _) = on_adapter(dedicated, &[], luid);
    let (local, _) = on_adapter(local, &[], luid);
    let evicted_mib = pids
        .iter()
        .map(|pid| {
            let held = dedicated.get(pid).copied().unwrap_or(0);
            held.saturating_sub(local.get(pid).copied().unwrap_or(0))
        })
        .sum();
    let others_mib = dedicated
        .iter()
        .filter(|(pid, _)| !pids.contains(pid))
        .map(|(_, mib)| *mib)
        .sum();
    ProofCardUse {
        evicted_mib,
        others_mib,
        card_full: None,
    }
}

/// Whether an adapter's own `Dedicated Usage` (MiB) is the same reading as `nvidia-smi`'s
/// `memory.used`: within 256 MiB or 5%, the two being taken moments apart.
fn agrees_with_smi(adapter_mib: u64, smi_used_mib: u64) -> bool {
    adapter_mib.abs_diff(smi_used_mib) <= (smi_used_mib / 20).max(256)
}

/// `(pid, luid, phys)` from a `GPU Process Memory` instance `pid_<pid>_luid_0x<8>_0x<8>_phys_<n>`,
/// or `(None, luid, phys)` from a `GPU Adapter Memory` one `luid_..._phys_<n>`. The hex comes in
/// either case (PDH gives upper, `Get-Counter` lower); a trailing `#k` PDH adds to a duplicate name
/// is ignored.
fn parse_instance(name: &str) -> Option<(Option<u32>, AdapterLuid, u32)> {
    let lower = name.to_ascii_lowercase();
    let (pid, rest) = match lower.strip_prefix("pid_") {
        Some(r) => {
            let (p, r) = r.split_once('_')?;
            (Some(p.parse().ok()?), r)
        }
        None => (None, lower.as_str()),
    };
    let rest = rest.strip_prefix("luid_0x")?;
    let (high, rest) = rest.split_once("_0x")?;
    let (low, rest) = rest.split_once("_phys_")?;
    let phys: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((
        pid,
        AdapterLuid {
            high: u32::from_str_radix(high, 16).ok()?,
            low: u32::from_str_radix(low, 16).ok()?,
        },
        phys.parse().ok()?,
    ))
}

/// The one adapter at `pci` (`0000:bb:dd.f`) among `(luid, bus, device, function)`: `None` unless
/// exactly one is. The PCI segment must be 0 (an adapter address carries none), and a software
/// adapter's all-ones address never matches.
fn luid_for_pci(adapters: &[(AdapterLuid, u32, u32, u32)], pci: &str) -> Option<AdapterLuid> {
    let mut hits = adapters.iter().filter(|(_, b, d, f)| {
        *b <= 255 && *d <= 31 && *f <= 7 && format!("0000:{b:02x}:{d:02x}.{f:x}") == pci
    });
    let first = hits.next()?.0;
    hits.next().is_none().then_some(first)
}

/// The PCI vendor id of each display adapter, by its PCI address (`0000:bb:dd.f`), from the kernel
/// thunks D3D itself uses (no admin, no vendor library): `None` if they cannot be listed.
pub(crate) fn adapter_vendors() -> Option<Vec<(String, u32)>> {
    Some(
        d3dkmt::vendors()?
            .into_iter()
            .filter(|(b, d, f, _)| *b <= 255 && *d <= 31 && *f <= 7)
            .map(|(b, d, f, vendor)| (format!("0000:{b:02x}:{d:02x}.{f:x}"), vendor))
            .collect(),
    )
}

/// MiB each pid holds on `luid`, summed over its `phys_<n>` parts, and the adapter's own figure in
/// MiB, if listed.
fn on_adapter(
    processes: &[(String, u64)],
    adapters: &[(String, u64)],
    luid: AdapterLuid,
) -> (HashMap<u32, u64>, Option<u64>) {
    let mut by_pid: HashMap<u32, u64> = HashMap::new();
    for (name, bytes) in processes {
        if let Some((Some(pid), l, _)) = parse_instance(name) {
            if l == luid {
                let held = by_pid.entry(pid).or_insert(0);
                *held = held.saturating_add(*bytes);
            }
        }
    }
    let mut adapter: Option<u64> = None;
    for (name, bytes) in adapters {
        if let Some((None, l, _)) = parse_instance(name) {
            if l == luid {
                adapter = Some(adapter.unwrap_or(0).saturating_add(*bytes));
            }
        }
    }
    (
        by_pid
            .into_iter()
            .map(|(pid, bytes)| (pid, bytes.div_ceil(MIB)))
            .collect(),
        adapter.map(|bytes| bytes.div_ceil(MIB)),
    )
}

/// Every display adapter's LUID and PCI address, from the kernel thunks D3D itself uses (no admin).
mod d3dkmt {
    use super::{c_void, AdapterLuid};

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct AdapterInfo {
        h_adapter: u32,
        luid: Luid,
        num_of_sources: u32,
        precise_present_regions_preferred: i32,
    }

    #[repr(C)]
    struct EnumAdapters2 {
        num_adapters: u32,
        p_adapters: *mut AdapterInfo,
    }

    #[repr(C)]
    struct QueryAdapterInfo {
        h_adapter: u32,
        kind: i32,
        data: *mut c_void,
        size: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct AdapterAddress {
        bus: u32,
        device: u32,
        function: u32,
    }

    #[repr(C)]
    struct CloseAdapter {
        h_adapter: u32,
    }

    /// `D3DKMT_QUERY_DEVICE_IDS`: a physical adapter's index in, its PCI ids out.
    #[repr(C)]
    #[derive(Default)]
    struct QueryDeviceIds {
        physical_adapter_index: u32,
        vendor_id: u32,
        device_id: u32,
        sub_vendor_id: u32,
        sub_system_id: u32,
        revision_id: u32,
        bus_type: u32,
    }

    /// `D3DKMT_SEGMENTSIZEINFO`: an adapter's memory sizes, in bytes.
    #[repr(C)]
    #[derive(Default)]
    struct SegmentSizeInfo {
        dedicated_video_memory: u64,
        dedicated_system_memory: u64,
        shared_system_memory: u64,
    }

    const KMTQAITYPE_GETSEGMENTSIZE: i32 = 3;
    const KMTQAITYPE_ADAPTERADDRESS: i32 = 6;
    const KMTQAITYPE_PHYSICALADAPTERDEVICEIDS: i32 = 31;
    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

    #[link(name = "gdi32")]
    extern "system" {
        fn D3DKMTEnumAdapters2(e: *mut EnumAdapters2) -> i32;
        fn D3DKMTQueryAdapterInfo(q: *mut QueryAdapterInfo) -> i32;
        fn D3DKMTCloseAdapter(c: *const CloseAdapter) -> i32;
    }

    /// `(luid, bus, device, function)` of every adapter, or `None` if they cannot be listed.
    pub(super) fn adapters() -> Option<Vec<(AdapterLuid, u32, u32, u32)>> {
        listed(false, false).map(|all| {
            all.into_iter()
                .map(|a| (a.luid, a.bus, a.device, a.function))
                .collect()
        })
    }

    /// The dedicated video memory of the adapter `luid`, in bytes, as its driver reports it, or
    /// `None` when it cannot be listed or read.
    pub(super) fn dedicated_bytes(luid: AdapterLuid) -> Option<u64> {
        listed(false, true)?
            .into_iter()
            .find(|a| a.luid == luid)?
            .dedicated
            .filter(|b| *b > 0)
    }

    /// `(bus, device, function, PCI vendor id)` of every adapter whose ids can be read, or `None`
    /// if they cannot be listed.
    pub(super) fn vendors() -> Option<Vec<(u32, u32, u32, u32)>> {
        listed(true, false).map(|all| {
            all.into_iter()
                .filter_map(|a| Some((a.bus, a.device, a.function, a.vendor?)))
                .collect()
        })
    }

    /// One adapter of [`listed`].
    struct Listed {
        luid: AdapterLuid,
        bus: u32,
        device: u32,
        function: u32,
        vendor: Option<u32>,
        dedicated: Option<u64>,
    }

    /// [`adapters`], each with its PCI vendor id when `with_vendor` asks for it and its dedicated
    /// video memory when `with_size` does, each when it can be read.
    fn listed(with_vendor: bool, with_size: bool) -> Option<Vec<Listed>> {
        let mut probe = EnumAdapters2 {
            num_adapters: 0,
            p_adapters: std::ptr::null_mut(),
        };
        // SAFETY: a null array asks only for a capacity.
        if unsafe { D3DKMTEnumAdapters2(&mut probe) } != 0 {
            return None;
        }
        let mut capacity = probe.num_adapters.max(16);
        // Adapters can appear between the calls.
        for _ in 0..3 {
            let mut buffer = vec![AdapterInfo::default(); capacity as usize];
            let mut list = EnumAdapters2 {
                num_adapters: capacity,
                p_adapters: buffer.as_mut_ptr(),
            };
            // SAFETY: `list` points at `capacity` writable records.
            match unsafe { D3DKMTEnumAdapters2(&mut list) } {
                0 => {}
                STATUS_BUFFER_TOO_SMALL => {
                    capacity = capacity.saturating_mul(2);
                    continue;
                }
                _ => return None,
            }
            let listed = (list.num_adapters as usize).min(buffer.len());
            let mut out = Vec::with_capacity(listed);
            for adapter in &buffer[..listed] {
                let mut address = AdapterAddress::default();
                let mut query = QueryAdapterInfo {
                    h_adapter: adapter.h_adapter,
                    kind: KMTQAITYPE_ADAPTERADDRESS,
                    data: (&mut address as *mut AdapterAddress).cast(),
                    size: std::mem::size_of::<AdapterAddress>() as u32,
                };
                // SAFETY: an open adapter handle and a buffer of the size the query names.
                if unsafe { D3DKMTQueryAdapterInfo(&mut query) } == 0 {
                    let vendor = with_vendor
                        .then(|| device_ids(adapter.h_adapter))
                        .flatten()
                        .map(|ids| ids.vendor_id);
                    let dedicated = with_size
                        .then(|| segment_sizes(adapter.h_adapter))
                        .flatten()
                        .map(|sizes| sizes.dedicated_video_memory);
                    out.push(Listed {
                        luid: AdapterLuid {
                            high: adapter.luid.high_part as u32,
                            low: adapter.luid.low_part,
                        },
                        bus: address.bus,
                        device: address.device,
                        function: address.function,
                        vendor,
                        dedicated,
                    });
                }
                // SAFETY: every handle the listing opened is closed, once.
                unsafe {
                    D3DKMTCloseAdapter(&CloseAdapter {
                        h_adapter: adapter.h_adapter,
                    })
                };
            }
            return Some(out);
        }
        None
    }

    /// The PCI ids of the open adapter `h_adapter`'s first physical adapter (WDDM 2.4 and up).
    fn device_ids(h_adapter: u32) -> Option<QueryDeviceIds> {
        let mut ids = QueryDeviceIds::default();
        let mut query = QueryAdapterInfo {
            h_adapter,
            kind: KMTQAITYPE_PHYSICALADAPTERDEVICEIDS,
            data: (&mut ids as *mut QueryDeviceIds).cast(),
            size: std::mem::size_of::<QueryDeviceIds>() as u32,
        };
        // SAFETY: an open adapter handle and a buffer of the size the query names.
        (unsafe { D3DKMTQueryAdapterInfo(&mut query) } == 0).then_some(ids)
    }

    /// The memory sizes of the open adapter `h_adapter`.
    fn segment_sizes(h_adapter: u32) -> Option<SegmentSizeInfo> {
        let mut sizes = SegmentSizeInfo::default();
        let mut query = QueryAdapterInfo {
            h_adapter,
            kind: KMTQAITYPE_GETSEGMENTSIZE,
            data: (&mut sizes as *mut SegmentSizeInfo).cast(),
            size: std::mem::size_of::<SegmentSizeInfo>() as u32,
        };
        // SAFETY: an open adapter handle and a buffer of the size the query names.
        (unsafe { D3DKMTQueryAdapterInfo(&mut query) } == 0).then_some(sizes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_records_have_the_kernel_layouts() {
            assert_eq!(std::mem::size_of::<AdapterInfo>(), 20);
            assert_eq!(std::mem::size_of::<EnumAdapters2>(), 16);
            assert_eq!(std::mem::size_of::<QueryAdapterInfo>(), 24);
            assert_eq!(std::mem::size_of::<AdapterAddress>(), 12);
            assert_eq!(std::mem::size_of::<QueryDeviceIds>(), 28);
            assert_eq!(std::mem::size_of::<SegmentSizeInfo>(), 24);
        }
    }
}

mod pdh {
    use super::c_void;

    const PDH_MORE_DATA: u32 = 0x8000_07D2;
    const PDH_FMT_LARGE: u32 = 0x0000_0400;

    #[repr(C)]
    struct FmtCounterValue {
        c_status: u32,
        // A union of LONG, double and LONGLONG; PDH_FMT_LARGE selects the LONGLONG.
        large_value: i64,
    }

    #[repr(C)]
    struct FmtCounterValueItem {
        name: *const u16,
        value: FmtCounterValue,
    }

    #[link(name = "pdh")]
    extern "system" {
        fn PdhOpenQueryW(data_source: *const u16, user_data: usize, query: *mut *mut c_void)
            -> u32;
        fn PdhAddEnglishCounterW(
            query: *mut c_void,
            path: *const u16,
            user_data: usize,
            counter: *mut *mut c_void,
        ) -> u32;
        fn PdhCollectQueryData(query: *mut c_void) -> u32;
        fn PdhGetFormattedCounterArrayW(
            counter: *mut c_void,
            format: u32,
            buffer_size: *mut u32,
            item_count: *mut u32,
            items: *mut FmtCounterValueItem,
        ) -> u32;
        fn PdhCloseQuery(query: *mut c_void) -> u32;
    }

    /// Every instance of a wildcard counter path, with its current value. `None` on any failure,
    /// including a counter set this Windows does not have.
    pub(super) fn read_counter_array(path: &str) -> Option<Vec<(String, u64)>> {
        read_counter_arrays(&[path])?.pop()
    }

    /// [`read_counter_array`] for each of `paths`, all from ONE collection: the same moment, so
    /// that two counters of one process can be compared.
    pub(super) fn read_counter_arrays(paths: &[&str]) -> Option<Vec<Vec<(String, u64)>>> {
        let mut query = std::ptr::null_mut();
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let result = (|| {
            let mut counters = Vec::with_capacity(paths.len());
            for path in paths {
                let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
                let mut counter = std::ptr::null_mut();
                if unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } != 0 {
                    return None;
                }
                counters.push(counter);
            }
            // Instantaneous counters: one sample is a reading.
            if unsafe { PdhCollectQueryData(query) } != 0 {
                return None;
            }
            counters.into_iter().map(instances).collect()
        })();
        unsafe { PdhCloseQuery(query) };
        result
    }

    /// The instances of a collected `counter`, with their values.
    fn instances(counter: *mut c_void) -> Option<Vec<(String, u64)>> {
        let (mut size, mut count) = (0u32, 0u32);
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_LARGE,
                &mut size,
                &mut count,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            return Some(Vec::new()); // no instances
        }
        if status != PDH_MORE_DATA {
            return None;
        }
        // The items, then the strings they point to, in one buffer of `size` bytes.
        let item_size = std::mem::size_of::<FmtCounterValueItem>();
        let mut buffer = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let items = buffer.as_mut_ptr().cast::<FmtCounterValueItem>();
        if unsafe {
            PdhGetFormattedCounterArrayW(counter, PDH_FMT_LARGE, &mut size, &mut count, items)
        } != 0
        {
            return None;
        }
        debug_assert!(count as usize * item_size <= buffer.len() * 8);
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let item = unsafe { &*items.add(i) };
            if item.value.c_status != 0 || item.name.is_null() {
                continue;
            }
            let name = unsafe {
                let len = (0..).take_while(|&n| *item.name.add(n) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(item.name, len))
            };
            out.push((name, item.value.large_value.max(0) as u64));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: AdapterLuid = AdapterLuid {
        high: 0,
        low: 0x00c3_ca54,
    };
    const OTHER: AdapterLuid = AdapterLuid {
        high: 0,
        low: 0x00c5_debb,
    };

    /// What Windows moved off the card is counted for the processes asked about, on this card only,
    /// and memory resident beyond what is allocated (counters a moment apart) never goes negative.
    /// A card is full within 1 GiB of its size, and unknown when either figure is.
    #[test]
    fn a_card_is_full_within_a_gib_of_its_size() {
        let rx9070xt = Some(16_304 * MIB);
        assert_eq!(card_is_full(Some(16_000), rx9070xt), Some(true));
        assert_eq!(card_is_full(Some(15_280), rx9070xt), Some(true));
        assert_eq!(card_is_full(Some(15_279), rx9070xt), Some(false));
        // The soak's readings: 2.5-13.5 GB in use.
        assert_eq!(card_is_full(Some(13_498), rx9070xt), Some(false));
        assert_eq!(card_is_full(Some(2_487), rx9070xt), Some(false));
        assert_eq!(card_is_full(None, rx9070xt), None);
        assert_eq!(card_is_full(Some(16_000), None), None);
    }

    #[test]
    fn evicted_memory_is_the_allocated_less_the_resident_on_this_card() {
        let mib = |n: u64| n * MIB;
        let dedicated = vec![
            // The server, paged out: 9,875 MiB allocated here, 9 resident.
            (
                "pid_100_luid_0x00000000_0x00c3ca54_phys_0".to_string(),
                mib(9_875),
            ),
            // Its worker, holding a little here, all resident.
            (
                "pid_101_luid_0x00000000_0x00c3ca54_phys_0".to_string(),
                mib(300),
            ),
            // The server's context on another card, evicted there: not this card's business.
            (
                "pid_100_luid_0x00000000_0x00c5debb_phys_0".to_string(),
                mib(500),
            ),
            // Another program, evicted too: not ours.
            (
                "pid_200_luid_0x00000000_0x00c3ca54_phys_0".to_string(),
                mib(2_048),
            ),
        ];
        let local = vec![
            (
                "pid_100_luid_0x00000000_0x00c3ca54_phys_0".to_string(),
                mib(9),
            ),
            (
                "pid_101_luid_0x00000000_0x00c3ca54_phys_0".to_string(),
                mib(310),
            ),
            ("pid_100_luid_0x00000000_0x00c5debb_phys_0".to_string(), 0),
            ("pid_200_luid_0x00000000_0x00c3ca54_phys_0".to_string(), 0),
        ];
        let evicted = |local: &[(String, u64)], luid, pids: &[u32]| {
            card_use(&dedicated, local, luid, pids).evicted_mib
        };
        assert_eq!(evicted(&local, CARD, &[100, 101]), 9_866);
        assert_eq!(evicted(&local, CARD, &[101]), 0);
        assert_eq!(evicted(&local, OTHER, &[100]), 500);
        // A process with no memory on the card, or no reading, has none evicted.
        assert_eq!(evicted(&local, CARD, &[999]), 0);
        // Resident and allocated alike: nothing evicted.
        assert_eq!(evicted(&dedicated, CARD, &[100, 101, 200]), 0);
        // Everyone else's memory on this card: the other program's, not ours, not another card's.
        assert_eq!(
            card_use(&dedicated, &local, CARD, &[100, 101]).others_mib,
            2_048
        );
        assert_eq!(
            card_use(&dedicated, &local, CARD, &[101]).others_mib,
            9_875 + 2_048
        );
        assert_eq!(card_use(&dedicated, &local, OTHER, &[100]).others_mib, 0);
    }

    #[test]
    fn an_instance_name_gives_its_pid_adapter_and_part() {
        assert_eq!(
            parse_instance("pid_25880_luid_0x00000000_0x00C3CA54_phys_0"),
            Some((Some(25880), CARD, 0))
        );
        assert_eq!(
            parse_instance("pid_25880_luid_0x00000000_0x00c3ca54_phys_0"),
            Some((Some(25880), CARD, 0))
        );
        assert_eq!(
            parse_instance("luid_0x00000000_0x00c5debb_phys_0"),
            Some((None, OTHER, 0))
        );
        // High part first, as the counters spell it.
        assert_eq!(
            parse_instance("luid_0x00000001_0x00000002_phys_1#2"),
            Some((None, AdapterLuid { high: 1, low: 2 }, 1))
        );
        assert_eq!(parse_instance("pid_x_luid_0x0_0x0_phys_0"), None);
        assert_eq!(parse_instance("pid_7_luid_0x00000000_0x00c3ca54"), None);
        assert_eq!(
            parse_instance("pid_7_luid_0x0000zz00_0x00c3ca54_phys_0"),
            None
        );
    }

    #[test]
    fn a_card_is_matched_to_the_one_adapter_at_its_pci_address() {
        let adapters = [
            (OTHER, 1, 0, 0),
            (CARD, 3, 0, 0),
            (
                AdapterLuid {
                    high: 0,
                    low: 0x16958,
                },
                17,
                0,
                0,
            ),
            (
                AdapterLuid {
                    high: 0,
                    low: 0x158f0,
                },
                0xFFFF_FFFF,
                0xFFFF,
                0xFFFF,
            ),
        ];
        let smi = crate::discovery::normalize_pci_bus_id("00000000:03:00.0");
        assert_eq!(luid_for_pci(&adapters, &smi), Some(CARD));
        assert_eq!(
            luid_for_pci(&adapters, "0000:11:00.0").map(|l| l.low),
            Some(0x16958)
        );
        assert_eq!(luid_for_pci(&adapters, "0001:03:00.0"), None);
        assert_eq!(luid_for_pci(&adapters, "0000:ff:ffff.ffff"), None);
        // Two adapters at one address: not knowable, so no match.
        assert_eq!(
            luid_for_pci(&[(CARD, 3, 0, 0), (OTHER, 3, 0, 0)], "0000:03:00.0"),
            None
        );
    }

    #[test]
    fn a_process_is_credited_only_with_what_it_holds_on_this_card() {
        const M: u64 = 1024 * 1024;
        let processes = vec![
            // On both cards: only its share here counts.
            (
                "pid_10_luid_0x00000000_0x00C3CA54_phys_0".to_string(),
                500 * M,
            ),
            (
                "pid_10_luid_0x00000000_0x00C5DEBB_phys_0".to_string(),
                15_000 * M,
            ),
            // Two parts of one adapter add up.
            (
                "pid_11_luid_0x00000000_0x00C3CA54_phys_0".to_string(),
                100 * M,
            ),
            (
                "pid_11_luid_0x00000000_0x00C3CA54_phys_1".to_string(),
                28 * M,
            ),
            // Only on the other card: nothing here.
            (
                "pid_12_luid_0x00000000_0x00C5DEBB_phys_0".to_string(),
                2_000 * M,
            ),
        ];
        let adapters = vec![
            ("luid_0x00000000_0x00C3CA54_phys_0".to_string(), 700 * M),
            ("luid_0x00000000_0x00C5DEBB_phys_0".to_string(), 17_000 * M),
        ];
        let (by_pid, adapter) = on_adapter(&processes, &adapters, CARD);
        assert_eq!(by_pid.get(&10), Some(&500));
        assert_eq!(by_pid.get(&11), Some(&128));
        assert_eq!(by_pid.get(&12), None);
        assert_eq!(adapter, Some(700));
        // An adapter with no instance of its own (a stale LUID) gives no figure to check against.
        let gone = AdapterLuid { high: 0, low: 1 };
        assert_eq!(on_adapter(&processes, &adapters, gone).1, None);
    }

    #[test]
    fn the_adapters_figure_must_agree_with_nvidia_smis() {
        assert!(agrees_with_smi(1586, 1581));
        assert!(agrees_with_smi(4, 0));
        assert!(agrees_with_smi(12_000, 11_500)); // 5% of a full 12 GB card
        assert!(!agrees_with_smi(1586, 17_000));
        assert!(!agrees_with_smi(700, 1_000));
    }

    /// Reported rows are left as they are, and with no card to match, nothing is filled in: one of
    /// ours left unreported makes the reading "no opinion".
    #[test]
    fn only_unreported_rows_are_filled_and_only_for_a_matched_card() {
        let ours = std::process::id();
        let rows = vec![(ours, None), (u32::MAX, None), (7, Some(512))];
        assert_eq!(fill_unreported(rows.clone(), None, 0), rows);
        assert_eq!(fill_unreported(rows.clone(), Some("0000:ff:1f.7"), 0), rows);
        assert_eq!(
            fill_unreported(vec![(7, Some(512))], None, 0),
            vec![(7, Some(512))]
        );
    }

    /// On this machine: a listed card's adapter is found, and the listing closes its handles.
    /// Every display adapter's size can be read without privileges, and a discrete card's is its
    /// VRAM, more than a GiB.
    #[test]
    fn the_adapters_sizes_can_be_read_without_privileges() {
        let Some(adapters) = d3dkmt::adapters() else {
            return;
        };
        let sizes: Vec<u64> = adapters
            .iter()
            .filter_map(|(luid, ..)| d3dkmt::dedicated_bytes(*luid))
            .collect();
        eprintln!(
            "adapter sizes (MiB): {:?}",
            sizes.iter().map(|b| b / MIB).collect::<Vec<_>>()
        );
        assert!(sizes.iter().all(|b| *b > 0));
    }

    #[test]
    fn the_adapters_can_be_listed_without_privileges() {
        let Some(adapters) = d3dkmt::adapters() else {
            return; // no display adapters (a service session)
        };
        for _ in 0..3 {
            assert_eq!(d3dkmt::adapters().map(|a| a.len()), Some(adapters.len()));
        }
    }

    /// On this machine: every PCI display adapter's vendor can be read, and is a GPU vendor's.
    #[test]
    fn the_adapters_vendors_can_be_read_without_privileges() {
        let (Some(vendors), Some(adapters)) = (adapter_vendors(), d3dkmt::adapters()) else {
            return; // no display adapters (a service session)
        };
        let at_pci = adapters
            .iter()
            .filter(|(_, b, d, f)| *b <= 255 && *d <= 31 && *f <= 7);
        assert_eq!(vendors.len(), at_pci.count(), "{vendors:x?}");
        for (pci, vendor) in &vendors {
            assert!(pci.starts_with("0000:"), "{pci}");
            assert_ne!(*vendor, 0, "{pci}");
        }
    }
}

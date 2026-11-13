//! Per-process GPU memory on Windows, where `nvidia-smi` cannot say.
//!
//! Under Windows' WDDM driver model `--query-compute-apps` reports `[N/A]` for every process's
//! memory, so `read_card_occupancy` cannot credit our own warm worker with what it holds, and the
//! VRAM gate has no opinion on any card one of our workers is on. Windows itself accounts each
//! process's video memory, in the `GPU Process Memory` performance counters Task Manager shows:
//! one instance per process and adapter, `pid_<pid>_luid_<luid>_phys_<n>`, whose `Dedicated
//! Usage` is the device memory that process holds there.

use std::collections::HashMap;
use std::ffi::c_void;

/// Device memory each process holds, in MiB, summed over the adapters it uses. `None` when the
/// counters cannot be read.
///
/// Summed over adapters rather than matched to one card: `nvidia-smi` gives no adapter LUID to
/// match by, and a worker uses only the card it was started for (`CUDA_VISIBLE_DEVICES`), so its
/// figure elsewhere is zero. The sum is used only for processes `nvidia-smi` lists on the card
/// being read.
pub(crate) fn dedicated_mib_by_pid() -> Option<HashMap<u32, u64>> {
    let mut by_pid: HashMap<u32, u64> = HashMap::new();
    for (instance, bytes) in pdh::read_counter_array(r"\GPU Process Memory(*)\Dedicated Usage")? {
        if let Some(pid) = pid_of_instance(&instance) {
            let held = by_pid.entry(pid).or_insert(0);
            *held = held.saturating_add(bytes);
        }
    }
    const MIB: u64 = 1024 * 1024;
    Some(
        by_pid
            .into_iter()
            .map(|(pid, bytes)| (pid, bytes.div_ceil(MIB)))
            .collect(),
    )
}

/// Fills in the memory `nvidia-smi` left unreported, from the counters. A process the counters
/// list nothing for holds no device memory. If the counters cannot be read, the rows are returned
/// as they were.
pub(crate) fn fill_unreported(apps: Vec<(u32, Option<u64>)>) -> Vec<(u32, Option<u64>)> {
    if apps.iter().all(|(_, mib)| mib.is_some()) {
        return apps;
    }
    let Some(held) = dedicated_mib_by_pid() else {
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

/// The pid in a `GPU Process Memory` instance name, `pid_<pid>_luid_..._phys_<n>`.
fn pid_of_instance(instance: &str) -> Option<u32> {
    instance
        .strip_prefix("pid_")?
        .split('_')
        .next()?
        .parse()
        .ok()
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
        let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut query = std::ptr::null_mut();
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let result = (|| {
            let mut counter = std::ptr::null_mut();
            if unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } != 0 {
                return None;
            }
            // Instantaneous counters: one sample is a reading.
            if unsafe { PdhCollectQueryData(query) } != 0 {
                return None;
            }
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
        })();
        unsafe { PdhCloseQuery(query) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pid_is_read_from_an_instance_name() {
        assert_eq!(
            pid_of_instance("pid_25880_luid_0x00000000_0x00e2dccb_phys_0"),
            Some(25880)
        );
        assert_eq!(pid_of_instance("luid_0x00000000_0x00e2dccb_phys_0"), None);
        assert_eq!(pid_of_instance("pid_x_luid"), None);
    }

    /// Only unreported rows are filled, and a process the counters do not list holds nothing.
    #[test]
    fn only_unreported_rows_are_filled() {
        let ours = std::process::id();
        let filled = fill_unreported(vec![(ours, None), (u32::MAX, None), (7, Some(512))]);
        assert_eq!(filled[2], (7, Some(512)));
        if dedicated_mib_by_pid().is_some() {
            assert!(filled[0].1.is_some());
            assert_eq!(filled[1], (u32::MAX, Some(0)));
        }
    }
}

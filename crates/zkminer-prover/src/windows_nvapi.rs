//! NVIDIA driver settings on Windows, read through NVAPI's driver-settings (DRS) interface.
//!
//! One setting matters to the miner: **CUDA - Sysmem Fallback Policy**. Under Windows' WDDM driver
//! model, when a CUDA allocation finds the card full the driver by default places it in system
//! memory instead of failing it. A proof that outgrows the card then keeps going, several times
//! slower: on a 12 GB RTX 4070, SP1 with 1.5 GiB of the card taken by a test allocation took 101 s for
//! a program that proves in 33 s, and risc0 at po2 21 ran at a quarter of its po2 19 rate. "Prefer
//! No Sysmem Fallback" makes such an allocation fail at once instead.
//!
//! Read only. NVAPI is loaded from the driver at run time (`nvapi64.dll`), so a host without an
//! NVIDIA driver simply reads nothing.
//!
//! Not yet confirmed: that a value set in the NVIDIA Control Panel reads back through this id. NVAPI
//! refuses to WRITE it (`NVAPI_SETTING_NOT_FOUND`), so it could not be set here to check, and on the
//! machine it was written on it reads as not set. Hence "not set in any profile read here", never "off".

use std::ffi::c_void;

/// The setting's DRS id, as listed in the driver's own settings table (in `nvapi64_impl.dll`,
/// beside `nvapi64.dll`) under "CUDA Sysmem Fallback Policy" with the values 0, 1 and 2. NVAPI's
/// public headers do not carry it, and no value set for it has been read back yet: a driver that
/// keeps the setting under another id reads as not set.
const CUDA_SYSMEM_FALLBACK_POLICY_ID: u32 = 0x10EC_ECC9;

/// A value of CUDA - Sysmem Fallback Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysmemFallback {
    /// Not set in any profile read here: the driver's default would apply, which falls back.
    NotSet,
    /// 0: "Driver Default", which falls back.
    DriverDefault,
    /// 1: "Prefer No Sysmem Fallback".
    PreferNoFallback,
    /// 2: "Prefer Sysmem Fallback".
    PreferFallback,
    /// A value this build does not know.
    Other(u32),
}

impl SysmemFallback {
    fn from_value(v: u32) -> Self {
        match v {
            0 => Self::DriverDefault,
            1 => Self::PreferNoFallback,
            2 => Self::PreferFallback,
            v => Self::Other(v),
        }
    }

    /// Whether an allocation that finds the card full goes to system memory; `None` for a value this
    /// build does not know.
    pub fn falls_back(self) -> Option<bool> {
        match self {
            Self::PreferNoFallback => Some(false),
            Self::Other(_) => None,
            _ => Some(true),
        }
    }
}

impl std::fmt::Display for SysmemFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSet => f.write_str(
                "not set in any profile read here (the driver default falls back; a driver \
                     that keeps the setting under another id also reads this way)",
            ),
            Self::DriverDefault => f.write_str("Driver Default (falls back)"),
            Self::PreferNoFallback => f.write_str("Prefer No Sysmem Fallback"),
            Self::PreferFallback => f.write_str("Prefer Sysmem Fallback"),
            Self::Other(v) => write!(f, "unknown value {v}"),
        }
    }
}

/// The policy in the global profile, and for each program asked about, what that program runs
/// with: its own profile's value if it has one that sets it, else the global.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysmemFallbackPolicy {
    pub global: SysmemFallback,
    pub programs: Vec<(String, SysmemFallback)>,
}

/// Read the policy, globally and for each of `programs` (executable names, e.g.
/// `zkminer-prove-sp1.exe`). `None` when NVAPI cannot be loaded or its settings cannot be read.
pub fn cuda_sysmem_fallback_policy(programs: &[&str]) -> Option<SysmemFallbackPolicy> {
    let api = Nvapi::load()?;
    let session = api.session()?;
    let global = {
        let mut profile = std::ptr::null_mut();
        // SAFETY: a live session and an out-pointer to a local.
        if unsafe { (api.get_current_global_profile)(session.0, &mut profile) } != 0 {
            return None;
        }
        api.setting(session.0, profile)?
    };
    let mut out = Vec::new();
    for name in programs {
        let wide = wide_name(name)?;
        let mut app = Box::new(Application::new());
        let mut profile = std::ptr::null_mut();
        // SAFETY: a live session, a NUL-terminated name in a 2048-unit buffer, and out-pointers to
        // a local and to a versioned application record.
        let rc = unsafe {
            (api.find_application_by_name)(session.0, wide.as_ptr(), &mut profile, &mut *app)
        };
        let effective = match rc {
            0 => match api.setting(session.0, profile)? {
                SysmemFallback::NotSet => global,
                set => set,
            },
            NVAPI_EXECUTABLE_NOT_FOUND => global,
            _ => return None,
        };
        out.push((name.to_string(), effective));
    }
    Some(SysmemFallbackPolicy {
        global,
        programs: out,
    })
}

const NVAPI_SETTING_NOT_FOUND: i32 = -160;
const NVAPI_EXECUTABLE_NOT_FOUND: i32 = -166;

/// `NVDRS_SETTING_V1`: 12,320 bytes, version 1.
#[repr(C)]
struct Setting {
    version: u32,
    name: [u16; 2048],
    id: u32,
    kind: u32,
    location: u32,
    is_current_predefined: u32,
    is_predefined_valid: u32,
    predefined: [u32; 1025],
    current: [u32; 1025],
}

impl Setting {
    fn new() -> Self {
        Setting {
            version: std::mem::size_of::<Setting>() as u32 | (1 << 16),
            name: [0; 2048],
            id: 0,
            kind: 0,
            location: 0,
            is_current_predefined: 0,
            is_predefined_valid: 0,
            predefined: [0; 1025],
            current: [0; 1025],
        }
    }
}

/// `NVDRS_APPLICATION_V1`: 12,296 bytes, version 1.
#[repr(C)]
struct Application {
    version: u32,
    is_predefined: u32,
    app_name: [u16; 2048],
    user_friendly_name: [u16; 2048],
    launcher: [u16; 2048],
}

impl Application {
    fn new() -> Self {
        Application {
            version: std::mem::size_of::<Application>() as u32 | (1 << 16),
            is_predefined: 0,
            app_name: [0; 2048],
            user_friendly_name: [0; 2048],
            launcher: [0; 2048],
        }
    }
}

/// `name` as an `NvAPI_UnicodeString`: UTF-16, NUL-terminated, 2048 units. `None` if too long.
fn wide_name(name: &str) -> Option<Box<[u16; 2048]>> {
    let mut buf = Box::new([0u16; 2048]);
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() >= buf.len() {
        return None;
    }
    buf[..units.len()].copy_from_slice(&units);
    Some(buf)
}

type Handle = *mut c_void;

type QueryInterface = unsafe extern "C" fn(u32) -> *mut c_void;
type Initialize = unsafe extern "C" fn() -> i32;
type CreateSession = unsafe extern "C" fn(*mut Handle) -> i32;
type SessionCall = unsafe extern "C" fn(Handle) -> i32;
type GetGlobalProfile = unsafe extern "C" fn(Handle, *mut Handle) -> i32;
type GetSetting = unsafe extern "C" fn(Handle, Handle, u32, *mut Setting) -> i32;
type FindApplication =
    unsafe extern "C" fn(Handle, *const u16, *mut Handle, *mut Application) -> i32;

/// The NVAPI entry points used here, by their interface ids (NVAPI's `nvapi_interface.h`).
struct Nvapi {
    create_session: CreateSession,
    destroy_session: SessionCall,
    load_settings: SessionCall,
    get_current_global_profile: GetGlobalProfile,
    get_setting: GetSetting,
    find_application_by_name: FindApplication,
}

/// A DRS session, destroyed when dropped.
struct Session<'a>(Handle, &'a Nvapi);

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // SAFETY: a session this created and nothing else holds.
        unsafe { (self.1.destroy_session)(self.0) };
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

/// `LoadLibraryExW`: search System32 only, where the driver installs `nvapi64.dll`. Not the default
/// order, which tries the executable's directory first and the current one before `PATH`.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

impl Nvapi {
    fn load() -> Option<Self> {
        let dll: Vec<u16> = "nvapi64.dll".encode_utf16().chain([0]).collect();
        // SAFETY: a NUL-terminated name, no file handle (reserved); the module stays loaded for the
        // life of the process.
        let module = unsafe {
            LoadLibraryExW(
                dll.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return None;
        }
        // SAFETY: a loaded module and a NUL-terminated export name.
        let query = unsafe { GetProcAddress(module, c"nvapi_QueryInterface".as_ptr().cast()) };
        if query.is_null() {
            return None;
        }
        // SAFETY: `nvapi_QueryInterface` takes an interface id and returns its entry point or null.
        let query = unsafe { std::mem::transmute::<*mut c_void, QueryInterface>(query) };
        let entry = |id: u32| {
            // SAFETY: as above.
            let f = unsafe { query(id) };
            (!f.is_null()).then_some(f)
        };
        use std::mem::transmute as cast;
        let initialize = entry(0x0150_E828)?;
        // SAFETY: each pointer is the entry point NVAPI returned for that id, whose C signature
        // the type it is cast to states.
        unsafe {
            if cast::<*mut c_void, Initialize>(initialize)() != 0 {
                return None;
            }
            Some(Nvapi {
                create_session: cast::<*mut c_void, CreateSession>(entry(0x0694_D52E)?),
                destroy_session: cast::<*mut c_void, SessionCall>(entry(0xDAD9_CFF8)?),
                load_settings: cast::<*mut c_void, SessionCall>(entry(0x375D_BD6B)?),
                get_current_global_profile: cast::<*mut c_void, GetGlobalProfile>(entry(
                    0x617B_FF9F,
                )?),
                get_setting: cast::<*mut c_void, GetSetting>(entry(0x73BF_8338)?),
                find_application_by_name: cast::<*mut c_void, FindApplication>(entry(0xEEE5_66B2)?),
            })
        }
    }

    fn session(&self) -> Option<Session<'_>> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: an out-pointer to a local.
        if unsafe { (self.create_session)(&mut handle) } != 0 {
            return None;
        }
        let session = Session(handle, self);
        // SAFETY: the session just created.
        if unsafe { (self.load_settings)(session.0) } != 0 {
            return None;
        }
        Some(session)
    }

    /// The policy as `profile` sets it, `NotSet` when it does not, `None` on any other failure.
    fn setting(&self, session: Handle, profile: Handle) -> Option<SysmemFallback> {
        let mut setting = Box::new(Setting::new());
        // SAFETY: a live session and profile, and a versioned setting record.
        let rc = unsafe {
            (self.get_setting)(
                session,
                profile,
                CUDA_SYSMEM_FALLBACK_POLICY_ID,
                &mut *setting,
            )
        };
        /// `NVDRS_DWORD_TYPE`.
        const DWORD: u32 = 0;
        match rc {
            0 if setting.kind == DWORD => Some(SysmemFallback::from_value(setting.current[0])),
            0 => None,
            NVAPI_SETTING_NOT_FOUND => Some(SysmemFallback::NotSet),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The records must have the sizes NVAPI checks their version against.
    #[test]
    fn the_records_have_nvapis_sizes() {
        assert_eq!(std::mem::size_of::<Setting>(), 12_320);
        assert_eq!(std::mem::size_of::<Application>(), 12_296);
        assert_eq!(Setting::new().version, 0x1_3020);
        assert_eq!(Application::new().version, 0x1_3008);
    }

    /// On a host with an NVIDIA driver the policy reads; elsewhere it reads as nothing.
    #[test]
    fn the_policy_reads_where_there_is_a_driver() {
        let policy = cuda_sysmem_fallback_policy(&["zkminer-prove-sp1.exe"]);
        if let Some(p) = policy {
            assert_eq!(p.programs.len(), 1);
            eprintln!("{p:?}");
        }
        assert_eq!(
            SysmemFallback::from_value(1),
            SysmemFallback::PreferNoFallback
        );
        assert_eq!(SysmemFallback::PreferNoFallback.falls_back(), Some(false));
        assert_eq!(SysmemFallback::NotSet.falls_back(), Some(true));
        assert_eq!(SysmemFallback::Other(7).falls_back(), None);
    }
}

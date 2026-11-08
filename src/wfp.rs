//! Current filter metadata lookup only: no engine options or filters are changed.
use crate::model::{FilterEvidence, now_ms};

#[cfg(windows)]
pub fn filter(id: u64) -> FilterEvidence {
    use std::ptr;
    use windows_sys::{
        Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
        core::GUID,
    };
    struct Engine(HANDLE);
    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe {
                FwpmEngineClose0(self.0);
            }
        }
    }
    struct Allocation(*mut FWPM_FILTER0);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                FwpmFreeMemory0(&mut self.0.cast::<std::ffi::c_void>());
            }
        }
    }
    fn guid(g: &GUID) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            g.data1,
            g.data2,
            g.data3,
            g.data4[0],
            g.data4[1],
            g.data4[2],
            g.data4[3],
            g.data4[4],
            g.data4[5],
            g.data4[6],
            g.data4[7]
        )
    }
    // SAFETY: called only for a documented null-terminated string owned by the
    // live WFP allocation; copied before FwpmFreeMemory0, never exposed as ref.
    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        while len < 32768 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
    }
    let mut result = FilterEvidence {
        runtime_id: id,
        queried_ms: now_ms(),
        ..FilterEvidence::default()
    };
    unsafe {
        let mut engine = ptr::null_mut();
        let status = FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut engine);
        if status != 0 {
            result.status = format!("Unavailable: engine access Windows {status}");
            return result;
        }
        let engine = Engine(engine);
        let mut object = ptr::null_mut();
        let status = FwpmFilterGetById0(engine.0, id, &mut object);
        if status != 0 || object.is_null() {
            result.status = format!("Unavailable/deleted: Windows {status}");
            return result;
        }
        let allocation = Allocation(object);
        let f = &*allocation.0;
        result.name = wide(f.displayData.name);
        result.layer = guid(&f.layerKey);
        if !f.providerKey.is_null() {
            result.provider = guid(&*f.providerKey);
        }
        result.status="Current filter retrieved. Runtime IDs may be stale after policy/BFE changes; friendly-rule mapping is not established.".into();
    }
    result
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn missing_filter_or_denied_access_returns_explicit_evidence() {
        let result = super::filter(u64::MAX);
        assert_eq!(result.runtime_id, u64::MAX);
        assert!(result.queried_ms > 0);
        assert!(
            result.status.starts_with("Unavailable"),
            "A nonexistent filter must not be treated as a rule match"
        );
    }
}
#[cfg(not(windows))]
pub fn filter(id: u64) -> FilterEvidence {
    FilterEvidence {
        runtime_id: id,
        status: "Windows required".into(),
        ..FilterEvidence::default()
    }
}

//! DNS-SD discovery through the native Windows resolver (`dnsapi.dll`).
//!
//! The `mdns-sd` backend binds its own UDP socket on port 5353 and, on Windows, does not
//! receive multicast responses even when the OS resolver (Dnscache) sees the same devices.
//! This backend hands the query to the OS instead, via `DnsServiceBrowse` / `DnsServiceResolve`.
//!
//! Discovery runs in two stages because the browse callback delivers records
//! non-deterministically: some runs yield PTR records only, with no SRV in an eight-second
//! window. Stage A browses each service type and collects deduplicated instance names (using
//! any SRV/TXT/A records that happen to arrive as an opportunistic fast path). Stage B
//! resolves every instance that still lacks a port. A service type with no advertiser never
//! invokes the callback at all - no error and no negative result - so both stages are bounded
//! purely by the caller's timeout.

use super::{
    ALL_SCANNED_SERVICE_TYPES, COMPANION_LINK_SERVICE, DeviceDiscovery, DiscoveredDevice,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE, REMOTEPAIRING_SERVICE, build_device, dedup_key,
    enrich_and_filter, parse_instance_name,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_REQUEST_VERSION1, DNS_RECORDW, DNS_SERVICE_BROWSE_REQUEST,
    DNS_SERVICE_BROWSE_REQUEST_0, DNS_SERVICE_CANCEL, DNS_SERVICE_INSTANCE,
    DNS_SERVICE_RESOLVE_REQUEST, DNS_TXT_DATAW, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_PTR,
    DNS_TYPE_SRV, DNS_TYPE_TEXT, DnsServiceBrowse, DnsServiceBrowseCancel, DnsServiceFreeInstance,
    DnsServiceResolve, DnsServiceResolveCancel,
};
use windows_sys::core::PWSTR;

/// `DnsServiceBrowse` / `DnsServiceResolve` return this when the operation was accepted and
/// its callback will run later on a threadpool thread.
const DNS_REQUEST_PENDING: i32 = 9506;
const ERROR_SUCCESS: i32 = 0;

/// Query all interfaces. Verified to cover both WiFi and Ethernet on a dual-homed host.
const ALL_INTERFACES: u32 = 0;

/// Upper bound on a single UTF-16 string read out of an OS-owned buffer. DNS names cap at 255
/// bytes and TXT strings at 255 bytes per string, so this only exists to stop a runaway scan if
/// a buffer is not terminated.
const MAX_WIDE_CHARS: usize = 8192;
/// Upper bound on records walked in one browse callback chain.
const MAX_RECORD_CHAIN: usize = 512;
/// Upper bound on TXT strings / instance properties read from one record.
const MAX_PROPERTIES: usize = 256;
/// Upper bound on concurrent `DnsServiceResolve` operations.
const MAX_RESOLVES: usize = 32;

/// Browse events are produced on OS threadpool threads and drained by the scanning thread.
/// The OS re-delivers the same instance a dozen or more times per scan, so this is sized to
/// absorb bursts; a full channel drops the event rather than blocking a threadpool thread.
const BROWSE_CHANNEL_CAPACITY: usize = 512;

/// Stop browsing once no new instance has appeared for this long, so the remaining budget can
/// go to stage B.
const BROWSE_QUIET_PERIOD: Duration = Duration::from_millis(1200);

/// Fraction of the caller's timeout spent in stage A; the rest is stage B.
const BROWSE_BUDGET_FRACTION: f64 = 0.6;

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested without FFI)
// ---------------------------------------------------------------------------------------------

/// The name passed to the Win32 DNS-SD API. The shared service-type constants carry a trailing
/// dot for mDNS presentation; `dnsapi` wants the name without one.
fn query_name(service_type: &str) -> &str {
    service_type.trim_end_matches('.')
}

/// Resolve ordering for one service type. The RPPairing services are what this application
/// exists to find, so they are resolved first and are never the entries dropped when the
/// concurrency cap truncates the candidate list. Companion-link is metadata that only enriches
/// an RPPairing entry, so it ranks below RPPairing but still above the legacy lockdown services.
fn resolve_priority(service_type: &str) -> u8 {
    if service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE || service_type == REMOTEPAIRING_SERVICE
    {
        0
    } else if service_type == COMPANION_LINK_SERVICE {
        1
    } else {
        2
    }
}

/// Orders stage-B candidates deterministically: RPPairing services first, then by service index
/// and instance key. `HashMap` iteration order is arbitrary, so without this the concurrency cap
/// would drop a different, arbitrary subset on every scan.
fn order_resolve_candidates(
    mut candidates: Vec<(usize, String)>,
    service_types: &[String],
) -> Vec<(usize, String)> {
    candidates.sort_by(|a, b| {
        let pa = service_types
            .get(a.0)
            .map_or(u8::MAX, |s| resolve_priority(s));
        let pb = service_types
            .get(b.0)
            .map_or(u8::MAX, |s| resolve_priority(s));
        pa.cmp(&pb).then(a.0.cmp(&b.0)).then_with(|| a.1.cmp(&b.1))
    });
    candidates
}

/// Splits a `key=value` TXT string. A string with no `=` is a valueless key.
fn split_txt(entry: &str) -> (String, String) {
    match entry.split_once('=') {
        Some((k, v)) => (k.to_string(), v.to_string()),
        None => (entry.to_string(), String::new()),
    }
}

// ---------------------------------------------------------------------------------------------
// UTF-16 helpers
// ---------------------------------------------------------------------------------------------

/// NUL-terminated UTF-16 buffer for passing a Rust string to the Win32 API.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decodes an OS-owned NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 buffer that stays valid for the call.
unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < MAX_WIDE_CHARS {
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------------------------
// Stage A: DnsServiceBrowse
// ---------------------------------------------------------------------------------------------

enum BrowseEvent {
    /// A PTR record: the full instance name for the browsed service type.
    Instance {
        service_idx: usize,
        full_name: String,
    },
    /// An SRV record: owner name is the full instance name.
    Srv {
        service_idx: usize,
        full_name: String,
        target: String,
        port: u16,
    },
    /// A TXT record: owner name is the full instance name.
    Txt {
        service_idx: usize,
        full_name: String,
        strings: Vec<String>,
    },
    /// An A/AAAA record: owner name is a host name, not an instance name.
    Address { host: String, addr: IpAddr },
}

struct BrowseContext {
    service_idx: usize,
    tx: SyncSender<BrowseEvent>,
}

/// Keeps every allocation a single in-flight browse points at alive for the browse's lifetime.
struct BrowseHandle {
    /// `DNS_SERVICE_BROWSE_REQUEST::QueryName` points into this buffer.
    _query: Vec<u16>,
    /// The API writes its internal handle into `reserved`, so this must not move; it is also
    /// what `DnsServiceBrowseCancel` is given.
    cancel: Box<DNS_SERVICE_CANCEL>,
    /// The only strong reference to the context while the browse runs, owned by the OS as
    /// `pQueryContext`. Reclaimed once the cancel confirms no callback can still run;
    /// deliberately never reclaimed if the cancel fails.
    ctx_raw: *const BrowseContext,
}

/// Browse callback, invoked on a Windows threadpool thread.
///
/// `DnsServiceBrowseCancel` re-enters this function synchronously on the *cancelling* thread
/// with `status = ERROR_CANCELLED` and a NULL record. The NULL check below is therefore
/// mandatory, and the body must never take a lock the cancelling thread might already hold -
/// it only performs a non-blocking channel send.
unsafe extern "system" fn browse_callback(
    _status: u32,
    pquerycontext: *const c_void,
    pdnsrecord: *const DNS_RECORDW,
) {
    if pquerycontext.is_null() || pdnsrecord.is_null() {
        return;
    }
    // A panic must not unwind into the OS threadpool.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let ctx = unsafe { &*(pquerycontext as *const BrowseContext) };
        unsafe { walk_browse_records(pdnsrecord, ctx) };
    }));
}

/// Walks the linked record chain delivered to a browse callback.
///
/// The API retains ownership of this chain; it must not be passed to `DnsFree`.
///
/// # Safety
/// `head` must be a valid `DNS_RECORDW` chain owned by the caller of the browse callback.
unsafe fn walk_browse_records(head: *const DNS_RECORDW, ctx: &BrowseContext) {
    let mut cur = head;
    let mut visited = 0usize;

    while !cur.is_null() && visited < MAX_RECORD_CHAIN {
        visited += 1;
        let rec = unsafe { &*cur };
        let owner = unsafe { wide_to_string(rec.pName) };
        let idx = ctx.service_idx;

        let event = match rec.wType {
            DNS_TYPE_PTR => {
                let target = unsafe { wide_to_string(rec.Data.Ptr.pNameHost) };
                if target.is_empty() {
                    None
                } else {
                    Some(BrowseEvent::Instance {
                        service_idx: idx,
                        full_name: target,
                    })
                }
            }
            DNS_TYPE_SRV => {
                let srv = unsafe { rec.Data.Srv };
                if owner.is_empty() {
                    None
                } else {
                    Some(BrowseEvent::Srv {
                        service_idx: idx,
                        full_name: owner,
                        target: unsafe { wide_to_string(srv.pNameTarget) },
                        port: srv.wPort,
                    })
                }
            }
            DNS_TYPE_TEXT => {
                // `pStringArray` is a flexible array member, so the strings must be read
                // through the record the OS owns - never through a copy of the union, which
                // only has room for one element.
                let txt: *const DNS_TXT_DATAW = unsafe { ptr::addr_of!((*cur).Data.Txt) };
                let count = (unsafe { (*txt).dwStringCount } as usize).min(MAX_PROPERTIES);
                let base: *const PWSTR = unsafe { ptr::addr_of!((*txt).pStringArray) }.cast();
                let mut strings = Vec::with_capacity(count);
                for i in 0..count {
                    let s = unsafe { wide_to_string(*base.add(i)) };
                    if !s.is_empty() {
                        strings.push(s);
                    }
                }
                if owner.is_empty() || strings.is_empty() {
                    None
                } else {
                    Some(BrowseEvent::Txt {
                        service_idx: idx,
                        full_name: owner,
                        strings,
                    })
                }
            }
            DNS_TYPE_A => {
                // IP4_ADDRESS holds the four octets in network order inside a u32.
                let raw = unsafe { rec.Data.A.IpAddress };
                if owner.is_empty() {
                    None
                } else {
                    Some(BrowseEvent::Address {
                        host: owner,
                        addr: IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())),
                    })
                }
            }
            DNS_TYPE_AAAA => {
                let bytes = unsafe { rec.Data.AAAA.Ip6Address.IP6Byte };
                if owner.is_empty() {
                    None
                } else {
                    Some(BrowseEvent::Address {
                        host: owner,
                        addr: IpAddr::V6(Ipv6Addr::from(bytes)),
                    })
                }
            }
            _ => None,
        };

        if let Some(event) = event {
            // Non-blocking: a full channel drops the event rather than stalling a threadpool
            // thread. The OS re-delivers every instance many times per scan.
            let _ = ctx.tx.try_send(event);
        }

        cur = rec.pNext as *const DNS_RECORDW;
    }
}

/// What the two stages learned about one service instance.
#[derive(Default)]
struct InstanceState {
    /// Instance name as delivered, with original casing.
    full_name: String,
    hostname: Option<String>,
    port: Option<u16>,
    props: HashMap<String, String>,
    /// Addresses reported directly by `DnsServiceResolve`, which are authoritative for this
    /// instance and take precedence over A/AAAA records seen during the browse.
    resolved_addresses: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------------------------
// Stage B: DnsServiceResolve
// ---------------------------------------------------------------------------------------------

struct ResolveOutcome {
    hostname: String,
    port: u16,
    props: HashMap<String, String>,
    addresses: Vec<IpAddr>,
}

struct ResolveContext {
    idx: usize,
    /// Set by the completion callback before it publishes its result. Read on the scanning
    /// thread to decide whether a cancel is still needed; a completion that has already run
    /// has released its cancel handle, so cancelling it again would touch freed state.
    completed: AtomicBool,
    tx: SyncSender<(usize, Option<ResolveOutcome>)>,
}

struct ResolveHandle {
    /// `DNS_SERVICE_RESOLVE_REQUEST::QueryName` is a mutable `PWSTR` into this buffer.
    _query: Vec<u16>,
    cancel: Box<DNS_SERVICE_CANCEL>,
    ctx_raw: *const ResolveContext,
    ctx: Arc<ResolveContext>,
}

/// Resolve callback, invoked on a Windows threadpool thread.
///
/// Unlike the browse chain, the `DNS_SERVICE_INSTANCE` handed here is caller-owned: every
/// needed field is copied into owned Rust types and the instance is then released with
/// `DnsServiceFreeInstance`. The free is deliberately outside the `catch_unwind` that guards
/// the copy, so a panic during copying still releases the instance.
unsafe extern "system" fn resolve_callback(
    status: u32,
    pquerycontext: *const c_void,
    pinstance: *const DNS_SERVICE_INSTANCE,
) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if status == 0 && !pinstance.is_null() {
            Some(unsafe { copy_instance(pinstance) })
        } else {
            None
        }
    }))
    .unwrap_or(None);

    if !pinstance.is_null() {
        unsafe { DnsServiceFreeInstance(pinstance) };
    }

    if pquerycontext.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(move || {
        let ctx = unsafe { &*(pquerycontext as *const ResolveContext) };
        // Published before the result, so the scanning thread never observes a delivered result
        // without also observing that this operation completed.
        ctx.completed.store(true, Ordering::Release);
        let _ = ctx.tx.try_send((ctx.idx, outcome));
    }));
}

/// # Safety
/// `p` must point to a valid `DNS_SERVICE_INSTANCE` that stays valid for the call.
unsafe fn copy_instance(p: *const DNS_SERVICE_INSTANCE) -> ResolveOutcome {
    let inst = unsafe { &*p };

    let mut props = HashMap::new();
    if !inst.keys.is_null() && !inst.values.is_null() {
        let count = (inst.dwPropertyCount as usize).min(MAX_PROPERTIES);
        for i in 0..count {
            let key = unsafe { wide_to_string(*inst.keys.add(i)) };
            if key.is_empty() {
                continue;
            }
            let value = unsafe { wide_to_string(*inst.values.add(i)) };
            props.insert(key, value);
        }
    }

    let mut addresses = Vec::new();
    if !inst.ip4Address.is_null() {
        let raw = unsafe { *inst.ip4Address };
        addresses.push(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())));
    }
    if !inst.ip6Address.is_null() {
        let bytes = unsafe { (*inst.ip6Address).IP6Byte };
        addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
    }

    ResolveOutcome {
        hostname: unsafe { wide_to_string(inst.pszHostName) },
        port: inst.wPort,
        props,
        addresses,
    }
}

// ---------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------

pub struct WindowsDnsSdDiscovery {
    service_types: Vec<String>,
}

impl WindowsDnsSdDiscovery {
    pub fn new() -> Self {
        Self {
            service_types: ALL_SCANNED_SERVICE_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Default for WindowsDnsSdDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceDiscovery for WindowsDnsSdDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        let service_types = self.service_types.clone();

        tokio::task::spawn_blocking(move || scan(&service_types, timeout))
            .await
            .map_err(|e| crate::Error::Other(format!("Windows DNS-SD scan task failed: {e}")))?
    }
}

fn scan(service_types: &[String], timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
    let start = Instant::now();
    let total_deadline = start + timeout;
    let browse_deadline = start + timeout.mul_f64(BROWSE_BUDGET_FRACTION);

    let (instances, host_addresses) = browse_stage(service_types, browse_deadline)?;
    let instances = resolve_stage(service_types, instances, total_deadline);

    let mut devices: HashMap<(String, String), DiscoveredDevice> = HashMap::new();
    for ((service_idx, _), state) in instances {
        let Some(service_type) = service_types.get(service_idx) else {
            continue;
        };
        let Some(port) = state.port else {
            log::debug!(
                "Windows DNS-SD: dropping {} ({}) - no port after resolve",
                state.full_name,
                service_type
            );
            continue;
        };

        let hostname = state.hostname.clone().unwrap_or_default();
        let instance_name = parse_instance_name(&state.full_name, service_type);

        let mut addresses = state.resolved_addresses.clone();
        for addr in host_addresses
            .get(&hostname.trim_end_matches('.').to_ascii_lowercase())
            .into_iter()
            .flatten()
        {
            if !addresses.contains(addr) {
                addresses.push(*addr);
            }
        }

        log::debug!(
            "Windows DNS-SD resolved: instance={instance_name} host={hostname} service={service_type} port={port} addrs={addresses:?}"
        );

        let device = build_device(
            &instance_name,
            &hostname,
            service_type,
            Some(port),
            &addresses,
            &state.props,
        );
        devices.insert(dedup_key(&hostname, &instance_name, service_type), device);
    }

    Ok(enrich_and_filter(devices.into_values().collect()))
}

fn browse_stage(
    service_types: &[String],
    deadline: Instant,
) -> crate::Result<(
    HashMap<(usize, String), InstanceState>,
    HashMap<String, Vec<IpAddr>>,
)> {
    let (tx, rx) = sync_channel::<BrowseEvent>(BROWSE_CHANNEL_CAPACITY);
    let mut handles: Vec<BrowseHandle> = Vec::with_capacity(service_types.len());

    for (idx, service_type) in service_types.iter().enumerate() {
        let query = to_wide(query_name(service_type));
        let ctx = Arc::new(BrowseContext {
            service_idx: idx,
            tx: tx.clone(),
        });
        // The OS holds this strong reference for as long as a callback can be in flight, so an
        // in-flight threadpool callback can never see a freed context.
        let ctx_raw = Arc::into_raw(ctx);
        let mut cancel = Box::new(DNS_SERVICE_CANCEL {
            reserved: ptr::null_mut(),
        });

        let request = DNS_SERVICE_BROWSE_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex: ALL_INTERFACES,
            QueryName: query.as_ptr(),
            Anonymous: DNS_SERVICE_BROWSE_REQUEST_0 {
                pBrowseCallback: Some(browse_callback),
            },
            pQueryContext: ctx_raw as *mut c_void,
        };

        let status = unsafe { DnsServiceBrowse(&request, &mut *cancel) };
        if status == ERROR_SUCCESS || status == DNS_REQUEST_PENDING {
            handles.push(BrowseHandle {
                _query: query,
                cancel,
                ctx_raw,
            });
        } else {
            log::warn!("DnsServiceBrowse({service_type}) failed with status {status}");
            // The browse never started, so no callback can be pending.
            drop(unsafe { Arc::from_raw(ctx_raw) });
        }
    }

    if handles.is_empty() {
        return Err(crate::Error::Other(
            "DnsServiceBrowse failed for every service type".to_string(),
        ));
    }
    drop(tx);

    let mut instances: HashMap<(usize, String), InstanceState> = HashMap::new();
    let mut host_addresses: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut last_progress = Instant::now();

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        // A service type with no advertiser never fires its callback, so an expired poll is a
        // normal outcome and never an error.
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(200));
        match rx.recv_timeout(wait) {
            Ok(event) => {
                if apply_browse_event(event, &mut instances, &mut host_addresses) {
                    last_progress = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if !instances.is_empty() && last_progress.elapsed() >= BROWSE_QUIET_PERIOD {
            break;
        }
    }

    // `DnsServiceBrowseCancel` re-enters `browse_callback` synchronously on this thread with a
    // NULL record before it returns, so callback dispatch for a browse is serialized against
    // this thread: once a cancel reports success, no callback is running for that browse and
    // none can be dispatched afterwards. That is what makes reclaiming the OS's reference safe.
    for handle in handles {
        let status = unsafe { DnsServiceBrowseCancel(&*handle.cancel) };
        if status == ERROR_SUCCESS {
            drop(unsafe { Arc::from_raw(handle.ctx_raw) });
        } else {
            // The browse is still live and its callback may still fire. Leak the context, the
            // cancel block and the query buffer rather than free memory the OS still points at:
            // a bounded leak on a path that should never happen beats a use-after-free.
            log::warn!(
                "DnsServiceBrowseCancel returned status {status}; leaking the browse context"
            );
            std::mem::forget(handle);
        }
    }

    // Events queued before the cancels completed are still worth keeping.
    while let Ok(event) = rx.try_recv() {
        apply_browse_event(event, &mut instances, &mut host_addresses);
    }

    Ok((instances, host_addresses))
}

/// Folds one browse event into the accumulators. Returns true when it added new information.
fn apply_browse_event(
    event: BrowseEvent,
    instances: &mut HashMap<(usize, String), InstanceState>,
    host_addresses: &mut HashMap<String, Vec<IpAddr>>,
) -> bool {
    match event {
        BrowseEvent::Instance {
            service_idx,
            full_name,
        } => {
            let key = (
                service_idx,
                full_name.trim_end_matches('.').to_ascii_lowercase(),
            );
            match instances.entry(key) {
                std::collections::hash_map::Entry::Occupied(_) => false,
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(InstanceState {
                        full_name,
                        ..Default::default()
                    });
                    true
                }
            }
        }
        BrowseEvent::Srv {
            service_idx,
            full_name,
            target,
            port,
        } => {
            let key = (
                service_idx,
                full_name.trim_end_matches('.').to_ascii_lowercase(),
            );
            let state = instances.entry(key).or_insert_with(|| InstanceState {
                full_name,
                ..Default::default()
            });
            let changed = state.port != Some(port);
            state.port = Some(port);
            if !target.is_empty() {
                state.hostname = Some(target);
            }
            changed
        }
        BrowseEvent::Txt {
            service_idx,
            full_name,
            strings,
        } => {
            let key = (
                service_idx,
                full_name.trim_end_matches('.').to_ascii_lowercase(),
            );
            let state = instances.entry(key).or_insert_with(|| InstanceState {
                full_name,
                ..Default::default()
            });
            let mut changed = false;
            for entry in strings {
                let (k, v) = split_txt(&entry);
                if state.props.insert(k, v).is_none() {
                    changed = true;
                }
            }
            changed
        }
        BrowseEvent::Address { host, addr } => {
            let list = host_addresses
                .entry(host.trim_end_matches('.').to_ascii_lowercase())
                .or_default();
            if list.contains(&addr) {
                false
            } else {
                list.push(addr);
                true
            }
        }
    }
}

/// Resolves every instance that still lacks a port or arrived with no TXT properties. All
/// resolves are issued up front and awaited together so one slow instance does not consume the
/// whole budget.
///
/// An instance that got an SRV record but no TXT still needs resolving: without properties it
/// maps to `DeviceType::Unknown` and the pairing UI filters it away.
fn resolve_stage(
    service_types: &[String],
    mut instances: HashMap<(usize, String), InstanceState>,
    deadline: Instant,
) -> HashMap<(usize, String), InstanceState> {
    let candidates: Vec<(usize, String)> = instances
        .iter()
        .filter(|(_, state)| state.port.is_none() || state.props.is_empty())
        .map(|(key, _)| key.clone())
        .collect();

    let mut pending = order_resolve_candidates(candidates, service_types);
    if pending.len() > MAX_RESOLVES {
        log::warn!(
            "{} instances need resolving but only {MAX_RESOLVES} run concurrently; \
             dropping {} lower-priority candidates this scan",
            pending.len(),
            pending.len() - MAX_RESOLVES
        );
        pending.truncate(MAX_RESOLVES);
    }

    if pending.is_empty() || Instant::now() >= deadline {
        return instances;
    }

    // Sized so a completion never has to drop its result.
    let (tx, rx) = sync_channel::<(usize, Option<ResolveOutcome>)>(pending.len() + 8);
    let mut handles: Vec<ResolveHandle> = Vec::with_capacity(pending.len());

    for (i, key) in pending.iter().enumerate() {
        let Some(state) = instances.get(key) else {
            continue;
        };
        // QueryName is a mutable PWSTR; the buffer must outlive the operation, so ownership
        // moves into the handle rather than ending with this loop iteration.
        let mut query = to_wide(state.full_name.trim_end_matches('.'));
        let ctx = Arc::new(ResolveContext {
            idx: i,
            completed: AtomicBool::new(false),
            tx: tx.clone(),
        });
        let ctx_raw = Arc::into_raw(ctx.clone());
        let mut cancel = Box::new(DNS_SERVICE_CANCEL {
            reserved: ptr::null_mut(),
        });

        let request = DNS_SERVICE_RESOLVE_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex: ALL_INTERFACES,
            QueryName: query.as_mut_ptr(),
            pResolveCompletionCallback: Some(resolve_callback),
            pQueryContext: ctx_raw as *mut c_void,
        };

        let status = unsafe { DnsServiceResolve(&request, &mut *cancel) };
        if status == ERROR_SUCCESS || status == DNS_REQUEST_PENDING {
            handles.push(ResolveHandle {
                _query: query,
                cancel,
                ctx_raw,
                ctx,
            });
        } else {
            log::debug!(
                "DnsServiceResolve({}) failed with status {status}",
                state.full_name
            );
            drop(unsafe { Arc::from_raw(ctx_raw) });
        }
    }

    if handles.is_empty() {
        return instances;
    }
    drop(tx);

    let mut outcomes: HashMap<usize, ResolveOutcome> = HashMap::new();
    let mut done = 0usize;
    while done < handles.len() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(200));
        match rx.recv_timeout(wait) {
            Ok((idx, outcome)) => {
                done += 1;
                if let Some(outcome) = outcome {
                    outcomes.insert(idx, outcome);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // Late completions whose results arrived after the deadline are still usable.
    while let Ok((idx, outcome)) = rx.try_recv() {
        if let Some(outcome) = outcome {
            outcomes.insert(idx, outcome);
        }
    }

    for handle in handles {
        // Read from the context rather than from the channel drain: the callback sets this
        // before publishing its result, so a completion that raced the drain is still seen here
        // and its cancel handle - already released by the API - is left alone.
        if handle.ctx.completed.load(Ordering::Acquire) {
            // The completion callback runs at most once and has already run.
            drop(unsafe { Arc::from_raw(handle.ctx_raw) });
            continue;
        }

        let status = unsafe { DnsServiceResolveCancel(&*handle.cancel) };
        if status == ERROR_SUCCESS {
            drop(unsafe { Arc::from_raw(handle.ctx_raw) });
        } else {
            // The resolve is still live and its callback may still fire. Leak rather than free
            // memory the OS still points at.
            log::warn!(
                "DnsServiceResolveCancel returned status {status}; leaking the resolve context"
            );
            std::mem::forget(handle);
        }
    }

    for (idx, outcome) in outcomes {
        let Some(key) = pending.get(idx) else {
            continue;
        };
        let Some(state) = instances.get_mut(key) else {
            continue;
        };
        if !outcome.hostname.is_empty() {
            state.hostname = Some(outcome.hostname);
        }
        // Instances are also resolved for their TXT properties alone, so a resolve that reports
        // no port must not clobber a port already learned from an SRV record.
        if outcome.port != 0 {
            state.port = Some(outcome.port);
        }
        for (k, v) in outcome.props {
            state.props.entry(k).or_insert(v);
        }
        state.resolved_addresses = outcome.addresses;
        log::debug!(
            "Windows DNS-SD resolve: {} -> port {} ({})",
            state.full_name,
            outcome.port,
            service_types
                .get(key.0)
                .map(String::as_str)
                .unwrap_or("unknown service")
        );
    }

    instances
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::APPLE_MOBDEV2_SERVICE;

    /// The instance-name, TXT-property and dedup-key mapping is shared with the `mdns-sd`
    /// backend and is tested in `super::super` so it runs on every platform. What follows is
    /// specific to this backend.
    #[test]
    fn query_name_strips_trailing_dot() {
        assert_eq!(
            query_name(REMOTEPAIRING_SERVICE),
            "_remotepairing._tcp.local"
        );
        assert_eq!(
            query_name(REMOTEPAIRING_MANUAL_PAIRING_SERVICE),
            "_remotepairing-manual-pairing._tcp.local"
        );
        assert_eq!(query_name("_x._tcp.local"), "_x._tcp.local");
    }

    #[test]
    fn to_wide_is_nul_terminated() {
        let w = to_wide("ab");
        assert_eq!(w, vec![b'a' as u16, b'b' as u16, 0]);
    }

    #[test]
    fn txt_split_handles_valueless_keys() {
        assert_eq!(
            split_txt("model=AppleTV14,1"),
            ("model".into(), "AppleTV14,1".into())
        );
        assert_eq!(split_txt("flag"), ("flag".into(), String::new()));
        assert_eq!(split_txt("k="), ("k".into(), String::new()));
    }

    #[test]
    fn resolve_candidates_put_rppairing_services_first() {
        let service_types: Vec<String> = ALL_SCANNED_SERVICE_TYPES
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Indices follow ALL_SCANNED_SERVICE_TYPES: 0 mobdev2, 1 pairable, 2 remotepairing,
        // 3 manual pairing, 4 companion-link.
        let candidates = vec![
            (0usize, "b-mobdev2".to_string()),
            (4usize, "e-companion".to_string()),
            (3usize, "d-manual".to_string()),
            (1usize, "a-pairable".to_string()),
            (2usize, "c-remotepairing".to_string()),
        ];

        let ordered = order_resolve_candidates(candidates.clone(), &service_types);
        assert_eq!(
            ordered.iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![2, 3, 4, 0, 1],
            "RPPairing services resolve first, companion-link next, legacy lockdown services last"
        );

        // Ordering is a pure function of the input set, not of HashMap iteration order.
        let mut shuffled = candidates;
        shuffled.reverse();
        assert_eq!(
            order_resolve_candidates(shuffled, &service_types),
            ordered,
            "ordering must be independent of the order candidates were collected in"
        );
    }

    #[test]
    fn resolve_priority_ranks_pairing_above_companion_link_above_legacy() {
        assert_eq!(resolve_priority(REMOTEPAIRING_MANUAL_PAIRING_SERVICE), 0);
        assert_eq!(resolve_priority(REMOTEPAIRING_SERVICE), 0);
        assert_eq!(resolve_priority(COMPANION_LINK_SERVICE), 1);
        assert_eq!(resolve_priority(APPLE_MOBDEV2_SERVICE), 2);
    }

    #[test]
    fn browse_events_accumulate_into_instance_state() {
        let mut instances = HashMap::new();
        let mut addrs = HashMap::new();
        let full = "Living Room._remotepairing._tcp.local".to_string();

        assert!(apply_browse_event(
            BrowseEvent::Instance {
                service_idx: 2,
                full_name: full.clone(),
            },
            &mut instances,
            &mut addrs,
        ));
        // The OS re-delivers the same instance many times; the repeat adds nothing.
        assert!(!apply_browse_event(
            BrowseEvent::Instance {
                service_idx: 2,
                full_name: full.clone(),
            },
            &mut instances,
            &mut addrs,
        ));
        assert!(apply_browse_event(
            BrowseEvent::Srv {
                service_idx: 2,
                full_name: full.clone(),
                target: "Living-Room.local".to_string(),
                port: 49152,
            },
            &mut instances,
            &mut addrs,
        ));
        assert!(apply_browse_event(
            BrowseEvent::Txt {
                service_idx: 2,
                full_name: full.clone(),
                strings: vec!["model=AppleTV14,1".to_string()],
            },
            &mut instances,
            &mut addrs,
        ));
        assert!(apply_browse_event(
            BrowseEvent::Address {
                host: "Living-Room.local".to_string(),
                addr: "10.0.0.5".parse().unwrap(),
            },
            &mut instances,
            &mut addrs,
        ));

        assert_eq!(instances.len(), 1);
        let state = instances.values().next().unwrap();
        assert_eq!(state.port, Some(49152));
        assert_eq!(state.hostname.as_deref(), Some("Living-Room.local"));
        assert_eq!(
            state.props.get("model").map(String::as_str),
            Some("AppleTV14,1")
        );
        assert_eq!(addrs.get("living-room.local").unwrap().len(), 1);
    }

    #[test]
    fn instances_from_different_service_types_stay_separate() {
        let mut instances = HashMap::new();
        let mut addrs = HashMap::new();
        for idx in [2usize, 3usize] {
            apply_browse_event(
                BrowseEvent::Instance {
                    service_idx: idx,
                    full_name: "Living Room._x._tcp.local".to_string(),
                },
                &mut instances,
                &mut addrs,
            );
        }
        assert_eq!(instances.len(), 2);
    }

    #[test]
    fn wide_round_trip() {
        let w = to_wide("Frankie\u{2019}s MacBook Pro");
        let s = unsafe { wide_to_string(w.as_ptr()) };
        assert_eq!(s, "Frankie\u{2019}s MacBook Pro");
        assert_eq!(unsafe { wide_to_string(std::ptr::null()) }, "");
    }

    #[tokio::test]
    #[ignore = "requires a device advertising DNS-SD on the local network"]
    async fn live_scan() {
        let devices = WindowsDnsSdDiscovery::new()
            .discover(Duration::from_secs(8))
            .await
            .unwrap();
        for d in &devices {
            println!(
                "{} type={:?} ip={:?} port={:?} service={}",
                d.name, d.device_type, d.ip_address, d.port, d.service_type
            );
        }
    }
}

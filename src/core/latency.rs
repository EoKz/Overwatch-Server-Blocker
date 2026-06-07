use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROBE_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_millis(900);
const MAX_PARALLEL_PROBES: usize = 6;

#[derive(Clone, Debug)]
pub struct LatencyProbe {
    pub target_id: String,
    pub ip: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct LatencyUpdate {
    pub target_id: String,
    pub result: LatencyResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LatencyResult {
    Ready { milliseconds: u32 },
    Timeout,
    Unavailable,
}

pub struct LatencyMonitor {
    receiver: Receiver<LatencyUpdate>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LatencyMonitor {
    pub fn start(probes: Vec<LatencyProbe>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                let cycle_started = Instant::now();

                for chunk in probes.chunks(MAX_PARALLEL_PROBES) {
                    if worker_stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let handles = chunk
                        .iter()
                        .cloned()
                        .map(|probe| {
                            let sender = sender.clone();
                            let stop = Arc::clone(&worker_stop);

                            thread::spawn(move || {
                                if stop.load(Ordering::Relaxed) {
                                    return;
                                }

                                let result = ping_ipv4(probe.ip, PROBE_TIMEOUT);
                                let _ = sender.send(LatencyUpdate {
                                    target_id: probe.target_id,
                                    result,
                                });
                            })
                        })
                        .collect::<Vec<_>>();

                    for handle in handles {
                        let _ = handle.join();
                    }
                }

                sleep_until_next_cycle(cycle_started, &worker_stop);
            }
        });

        Self {
            receiver,
            stop,
            handle: Some(handle),
        }
    }

    pub fn drain_updates(&self) -> Vec<LatencyUpdate> {
        let mut updates = Vec::new();

        while let Ok(update) = self.receiver.try_recv() {
            updates.push(update);
        }

        updates
    }
}

impl Drop for LatencyMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn first_ipv4_probe(probes: &[&'static str]) -> Option<Ipv4Addr> {
    probes.iter().find_map(|probe| match probe.parse().ok()? {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    })
}

fn sleep_until_next_cycle(cycle_started: Instant, stop: &AtomicBool) {
    let elapsed = cycle_started.elapsed();
    let remaining = PROBE_INTERVAL.saturating_sub(elapsed);
    let sleep_step = Duration::from_millis(100);
    let sleep_started = Instant::now();

    while sleep_started.elapsed() < remaining && !stop.load(Ordering::Relaxed) {
        thread::sleep(sleep_step.min(remaining.saturating_sub(sleep_started.elapsed())));
    }
}

#[cfg(windows)]
fn ping_ipv4(ip: Ipv4Addr, timeout: Duration) -> LatencyResult {
    use std::mem::size_of;

    use windows::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_SUCCESS, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    let handle = match unsafe { IcmpCreateFile() } {
        Ok(handle) => handle,
        Err(_) => return LatencyResult::Unavailable,
    };

    let request_data = [0u8; 32];
    let reply_size = size_of::<ICMP_ECHO_REPLY>() + request_data.len() + 8;
    let mut reply_buffer = vec![0u8; reply_size];
    let destination = u32::from_ne_bytes(ip.octets());

    let reply_count = unsafe {
        IcmpSendEcho(
            handle,
            destination,
            request_data.as_ptr().cast(),
            request_data.len() as u16,
            None,
            reply_buffer.as_mut_ptr().cast(),
            reply_buffer.len() as u32,
            timeout.as_millis() as u32,
        )
    };
    let _ = unsafe { IcmpCloseHandle(handle) };

    if reply_count == 0 {
        return LatencyResult::Timeout;
    }

    let reply = unsafe { &*(reply_buffer.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
    if reply.Status == IP_SUCCESS {
        LatencyResult::Ready {
            milliseconds: reply.RoundTripTime,
        }
    } else {
        LatencyResult::Timeout
    }
}

#[cfg(not(windows))]
fn ping_ipv4(_ip: Ipv4Addr, _timeout: Duration) -> LatencyResult {
    LatencyResult::Unavailable
}

#[cfg(test)]
mod tests {
    use super::first_ipv4_probe;

    #[test]
    fn picks_only_ipv4_probe() {
        assert_eq!(
            first_ipv4_probe(&["2600:1900::1", "34.95.128.1"]),
            Some("34.95.128.1".parse().expect("valid IPv4"))
        );
        assert_eq!(first_ipv4_probe(&["2600:1900::1"]), None);
    }
}

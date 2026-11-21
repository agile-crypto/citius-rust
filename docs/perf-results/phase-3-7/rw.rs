// N threads taking one shared RwLock for reading (and an Arc clone), 1 s each.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
fn run(t: usize, what: &str) -> u64 {
    let lock = Arc::new(RwLock::new(Arc::new([0u64; 8])));
    let stop = Arc::new(AtomicBool::new(false));
    let hs: Vec<_> = (0..t).map(|_| { let (l, s) = (lock.clone(), stop.clone()); let what = what.to_string();
        std::thread::spawn(move || { let mut n = 0u64; while !s.load(Ordering::Relaxed) {
            match what.as_str() {
                "rwlock" => { let g = l.read().unwrap(); std::hint::black_box(&*g); }
                "rwlock+arc" => { let a = l.read().unwrap().clone(); std::hint::black_box(&a); }
                _ => {}
            } n += 1; } n }) }).collect();
    std::thread::sleep(Duration::from_secs(1)); stop.store(true, Ordering::Relaxed);
    hs.into_iter().map(|h| h.join().unwrap()).sum()
}
fn main() { for what in ["rwlock", "rwlock+arc"] { for t in [1, 2, 4, 8, 12] {
    println!("{what:11} {t:2} threads: {:>11} ops/s", run(t, what)); } } }

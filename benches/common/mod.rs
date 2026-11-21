//! Shared by the benches: running variants interleaved (docs/performance.md
//! F4: on this machine, block measurements carry ±10–15 % of order and
//! code-layout effects, so small differences must be measured this way).

#![allow(dead_code)]

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Keeps a result alive so the work is not optimized away.
pub fn keep<T>(x: T) {
    black_box(x);
}

pub type Variant<'a> = (&'a str, Box<dyn FnMut() + 'a>);

pub fn median(v: &mut [u64]) -> f64 {
    v.sort_unstable();
    v[v.len() / 2] as f64 / 1000.0
}

pub fn interleave(title: &str, rounds: usize, slice: Duration, mut vs: Vec<Variant>) {
    let mut all: Vec<Vec<u64>> = vec![Vec::new(); vs.len()];
    let mut per_round: Vec<Vec<f64>> = vec![Vec::new(); vs.len()];
    for (_, f) in vs.iter_mut() {
        let t = Instant::now();
        while t.elapsed() < slice {
            f();
        }
    }
    for r in 0..rounds {
        // Rotate the start so no variant always follows the same one.
        for k in 0..vs.len() {
            let i = (k + r) % vs.len();
            let mut v = Vec::new();
            let t = Instant::now();
            while v.len() < 5 || t.elapsed() < slice {
                let s = Instant::now();
                (vs[i].1)();
                v.push(s.elapsed().as_nanos() as u64);
            }
            all[i].extend_from_slice(&v);
            per_round[i].push(median(&mut v));
        }
    }
    println!("\n== {title}: {rounds} rounds × {} ms per variant ==", slice.as_millis());
    println!(
        "{:<34} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "variant", "n", "median µs", "round min", "round max", "Δ vs 1st"
    );
    let base = median(&mut all[0].clone());
    for (i, (name, _)) in vs.iter().enumerate() {
        let m = median(&mut all[i]);
        let lo = per_round[i].iter().cloned().fold(f64::MAX, f64::min);
        let hi = per_round[i].iter().cloned().fold(0.0, f64::max);
        println!("{name:<34} {:>8} {m:>10.1} {lo:>10.1} {hi:>10.1} {:>+10.1}", all[i].len(), m - base);
    }
}

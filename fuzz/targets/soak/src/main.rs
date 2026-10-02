//! Seeded soak runner: random bytes -> the same `Engine::run` the AFL target uses. No AFL build.
//!
//!   hydration-fuzz-soak                 # soak (env: FUZZ_SECONDS, FUZZ_ITERS, FUZZ_SEED, FUZZ_LEN, FUZZ_OUT)
//!   hydration-fuzz-soak replay FILE...  # re-run inputs verbosely (soak findings or AFL crashes/queue)
//!   hydration-fuzz-soak seeds DIR [N]   # write N random inputs as an initial AFL corpus

use harness::{default_snapshot_path, set_verbose, Engine};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
	std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn splitmix(x: &mut u64) -> u64 {
	*x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
	let mut z = *x;
	z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
	z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
	z ^ (z >> 31)
}

pub fn input(seed: u64, max_len: usize) -> Vec<u8> {
	let mut s = seed;
	let len = 16 + (splitmix(&mut s) as usize) % max_len.max(1);
	(0..len).map(|_| splitmix(&mut s) as u8).collect()
}

fn main() {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if args.first().map(String::as_str) == Some("seeds") {
		// Initial AFL corpus: the same random inputs the soak runner would generate.
		let (dir, n) = (&args[1], args.get(2).and_then(|n| n.parse().ok()).unwrap_or(64u64));
		std::fs::create_dir_all(dir).unwrap();
		for i in 0..n {
			std::fs::write(format!("{dir}/seed-{i}"), input(i, 512)).unwrap();
		}
		return;
	}
	let t0 = Instant::now();
	let mut engine = Engine::new(&default_snapshot_path());
	println!("snapshot loaded in {:?}: {}", t0.elapsed(), engine.tables.summary());
	

	if args.first().map(String::as_str) == Some("replay") {
		set_verbose(std::env::var("FUZZ_VERBOSE").map(|v| v != "0").unwrap_or(true));
		let t = &engine.tables;
		println!("aave pool {:?}\nreserves {:#?}\nuni pools {:?}\nhsm collaterals {:?} hollar {}", t.aave_pool, t.reserves, t.uni_pools, t.hsm_collaterals, t.hollar);
		for f in &args[1..] {
			println!("=== {f}");
			engine.run(&std::fs::read(f).expect("read input"));
			println!("=== {f}: ok");
		}
		return;
	}

	set_verbose(env("FUZZ_VERBOSE", 0u8) == 1);
	let seconds = env("FUZZ_SECONDS", 60u64);
	let iters = env("FUZZ_ITERS", 0u64);
	let seed = env("FUZZ_SEED", t0.elapsed().as_nanos() as u64 ^ std::process::id() as u64);
	let max_len = env("FUZZ_LEN", 512usize);
	let out = std::env::var("FUZZ_OUT").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../findings").into());
	println!("soak seed={seed} len<={max_len} {}", if iters > 0 { format!("{iters} iters") } else { format!("{seconds}s") });

	// Remember the panic location; the message alone is too specific to dedup on.
	std::panic::set_hook(Box::new(|info| {
		let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
		LAST_PANIC.with(|p| *p.borrow_mut() = loc);
	}));

	let start = Instant::now();
	let mut findings: BTreeMap<String, (u64, String)> = BTreeMap::new();
	let (mut n, mut panics) = (0u64, 0u64);
	let mut s = seed;
	loop {
		if (iters > 0 && n >= iters) || (iters == 0 && start.elapsed().as_secs() >= seconds) {
			break;
		}
		let scenario_seed = splitmix(&mut s);
		let data = input(scenario_seed, max_len);
		if let Err(p) = catch_unwind(AssertUnwindSafe(|| engine.run(&data))) {
			panics += 1;
			let msg = p
				.downcast_ref::<String>()
				.cloned()
				.or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
				.unwrap_or_default();
			let kind = msg.strip_prefix("VIOLATION[").and_then(|m| m.split(']').next()).map(str::to_string);
			let at = msg.rsplit_once("\n  at ").map(|(_, at)| at.to_string());
			let key = kind.or(at).unwrap_or_else(|| LAST_PANIC.with(|p| p.borrow().clone()));
			let entry = findings.entry(key.clone()).or_insert((0, String::new()));
			entry.0 += 1;
			if entry.0 == 1 {
				std::fs::create_dir_all(&out).unwrap();
				let path = format!("{out}/{scenario_seed:016x}.bin");
				std::fs::write(&path, &data).unwrap();
				entry.1 = path.clone();
				println!("\n!! [{key}] {}\n   reproduce: cargo run --release -p hydration-fuzz-soak -- replay {path}\n", msg.lines().next().unwrap_or(""));
			}
		}
		n += 1;
		if n % 200 == 0 {
			println!("{n} scenarios, {:.1}/s, {panics} panics, {} unique", n as f64 / start.elapsed().as_secs_f64(), findings.len());
		}
	}
	let secs = start.elapsed().as_secs_f64();
	println!("done: {n} scenarios in {secs:.1}s ({:.1}/s), {panics} panics", n as f64 / secs);
	for (k, (c, p)) in &findings {
		println!("  {c:>6} x {k}  ->  {p}");
	}
}

thread_local! {
	static LAST_PANIC: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

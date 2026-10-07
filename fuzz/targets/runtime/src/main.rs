//! AFL++ (via ziggy) target. The snapshot is loaded before `fuzz!`, so AFL's fork server hands
//! every child the loaded state copy-on-write; each input only pays for the keys it touches.
//!
//! With `FUZZ_REPLAY_ARGS=1` the same binary instead runs every file (or directory of files) given
//! on the command line through the engine in one process. Built with `-Cinstrument-coverage` on
//! top of AFL's instrumentation, that is how `coverage.sh` collects a report without a third build.

fn main() {
	// AFL's persistent loop wraps the body in catch_unwind; the engine is reset per input anyway.
	let mut engine = std::panic::AssertUnwindSafe(harness::Engine::new(&harness::default_snapshot_path()));
	if std::env::var("FUZZ_REPLAY_ARGS").is_ok() {
		for path in std::env::args().skip(1) {
			let files: Vec<std::path::PathBuf> = match std::fs::read_dir(&path) {
				Ok(dir) => dir.flatten().map(|e| e.path()).collect(),
				Err(_) => vec![path.into()],
			};
			for f in files {
				if let Ok(data) = std::fs::read(&f) {
					let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.run(&data)));
				}
			}
		}
		return;
	}
	ziggy::fuzz!(|data: &[u8]| {
		engine.run(data);
	});
}

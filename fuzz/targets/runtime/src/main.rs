//! AFL++ (via ziggy) target. The snapshot is loaded before `fuzz!`, so AFL's fork server hands
//! every child the loaded state copy-on-write; each input only pays for the keys it touches.

fn main() {
	// AFL's persistent loop wraps the body in catch_unwind; the engine is reset per input anyway.
	let mut engine = std::panic::AssertUnwindSafe(harness::Engine::new(&harness::default_snapshot_path()));
	ziggy::fuzz!(|data: &[u8]| {
		engine.run(data);
	});
}

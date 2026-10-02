//! EVM plumbing: ABI encoding, view/impersonated calls, and the tracing listeners that give us
//! (a) the revert-data oracle for every call frame and (b) (contract, pc) coverage for AFL.

use crate::{oracle, Runtime};
use hydradx_runtime::evm::Executor;
use hydradx_traits::evm::{CallContext, CallResult, EVM};
use sp_core::{H160, U256};

pub type Exec = Executor<Runtime>;

pub fn selector(sig: &str) -> [u8; 4] {
	let h = sp_io::hashing::keccak_256(sig.as_bytes());
	[h[0], h[1], h[2], h[3]]
}

#[derive(Clone, Copy, Debug)]
pub enum Token {
	Address(H160),
	Uint(U256),
	Bool(bool),
}

pub fn encode(sig: &str, args: &[Token]) -> Vec<u8> {
	let mut out = selector(sig).to_vec();
	for a in args {
		let mut word = [0u8; 32];
		match a {
			Token::Address(h) => word[12..].copy_from_slice(h.as_bytes()),
			Token::Uint(u) => word = u.to_big_endian(),
			Token::Bool(b) => word[31] = *b as u8,
		}
		out.extend_from_slice(&word);
	}
	out
}

pub fn word(data: &[u8], i: usize) -> Option<U256> {
	data.get(i * 32..(i + 1) * 32).map(U256::from_big_endian)
}

pub fn word_addr(data: &[u8], i: usize) -> Option<H160> {
	data.get(i * 32 + 12..(i + 1) * 32).map(H160::from_slice)
}

pub fn succeeded(r: &CallResult) -> bool {
	matches!(r.exit_reason, evm::ExitReason::Succeed(_))
}

/// Read-only call (state rolled back).
pub fn view(contract: H160, data: Vec<u8>) -> Option<Vec<u8>> {
	let r = Exec::view(CallContext::new_view(contract), data, 5_000_000);
	succeeded(&r).then_some(r.value)
}

/// State-changing call as any address, no signature needed (Foundry `vm.prank`).
pub fn call_as(sender: H160, contract: H160, data: Vec<u8>, value: U256, gas: u64) -> CallResult {
	Exec::call(CallContext::new_call(contract, sender), data, value, gas)
}

// ---------- tracing ----------

/// Every call frame's exit goes through here: Solidity `Panic(uint256)` and the designated
/// INVALID opcode are the EVM's `assert!` and count as violations.
struct ExitListener {
	panic_ignore: &'static [u64],
	/// Code address of each open call frame, to name the contract in a violation.
	frames: Vec<H160>,
}

pub const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

impl evm::tracing::EventListener for ExitListener {
	fn event(&mut self, event: evm::tracing::Event<'_>) {
		use evm::tracing::Event::*;
		let (reason, return_value) = match event {
			Call { code_address, .. } | PrecompileSubcall { code_address, .. } => return self.frames.push(code_address),
			TransactCall { address, .. } => return self.frames.push(address),
			Exit { reason, return_value } => (reason, return_value),
			_ => return,
		};
		let at = self.frames.pop().unwrap_or_default();
		match reason {
			evm::ExitReason::Revert(_) if return_value.len() == 36 && return_value[..4] == PANIC_SELECTOR => {
				let code = U256::from_big_endian(&return_value[4..]).low_u64();
				if !self.panic_ignore.contains(&code) {
					oracle::violation("evm_panic", format!("Solidity Panic(0x{code:02x}) in {at:?}"));
				}
			}
			evm::ExitReason::Error(evm::ExitError::DesignatedInvalid) => {
				oracle::violation("evm_invalid", format!("INVALID (0xFE) opcode executed in {at:?}"))
			}
			_ => {}
		}
	}
}

/// Maps (contract, pc) of each executed opcode into AFL's shared coverage map so contract code
/// paths count as new coverage. No-op outside AFL builds.
struct StepListener;

#[cfg(fuzzing)]
extern "C" {
	static mut __afl_area_ptr: *mut u8;
	static __afl_map_size: u32;
}

impl evm_runtime::tracing::EventListener for StepListener {
	fn event(&mut self, event: evm_runtime::tracing::Event<'_>) {
		let evm_runtime::tracing::Event::Step { context, position, .. } = event else { return };
		let Ok(pc) = position else { return };
		let a = context.address.as_bytes();
		let h = u64::from_le_bytes(a[12..20].try_into().unwrap()) ^ (*pc as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
		bump(h);
	}
}

#[cfg(fuzzing)]
fn bump(h: u64) {
	// SAFETY: AFL's runtime maps `__afl_area_ptr` to at least `__afl_map_size` bytes before main.
	unsafe {
		let size = __afl_map_size as u64;
		if size == 0 || __afl_area_ptr.is_null() {
			return;
		}
		let p = __afl_area_ptr.add((h % size) as usize);
		*p = (*p).wrapping_add(1);
	}
}

#[cfg(not(fuzzing))]
fn bump(h: u64) {
	std::hint::black_box(h);
}

pub fn with_listeners<R>(cfg: &oracle::Config, f: impl FnOnce() -> R) -> R {
	let mut exit = ExitListener {
		panic_ignore: cfg.evm_panic_ignore,
		frames: vec![],
	};
	if !cfg.evm_revert {
		return run_steps(cfg, f);
	}
	evm::tracing::using(&mut exit, || run_steps(cfg, f))
}

fn run_steps<R>(cfg: &oracle::Config, f: impl FnOnce() -> R) -> R {
	if cfg.evm_coverage {
		evm_runtime::tracing::using(&mut StepListener, f)
	} else {
		f()
	}
}

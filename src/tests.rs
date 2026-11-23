//! Host tests for [`run`]: boot outcomes, the genesis guard, restart, and the
//! `NextCall` → timer mapping. Time is embassy-time's mock driver, so nothing
//! sleeps; `run` never returns, so a test polls it until it waits and then
//! drops it ("reboot" = drop and call `run` again on the same storage).

extern crate std;

use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;
use std::boxed::Box;
use std::cell::RefCell as StdRefCell;
use std::string::{String, ToString};
use std::vec::Vec;

use embassy_futures::poll_once;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, MockDriver};
use moonblokz_chain_types::{Block, MAX_BLOCK_SIZE};
use moonblokz_configuration::parameter;
use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE, PublicKeyTrait};
use moonblokz_storage::{
    ControlPlaneData, INIT_PARAMS_SIZE, MemoryBackend, StorageError, StorageIndex,
};

use super::*;

// The test chain: the blockchain suite's small profile.
const MAX_NODES: usize = 16;
const W: u32 = 16;
const H: u32 = 8;
const MAX_BLOCKS: usize = W as usize + 2 * H as usize;
const MAX_BRANCH_COUNT: usize = 4;
const MAX_BLOCK_UTXO_OUTPUT: usize = 16;
type Backend = MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>;

/// Chain-config content: `W`, `H`, the node cap and the build's scheme; every
/// other parameter takes its default.
static CONTENT: [u8; 23] = [
    4,
    0,
    parameter::ACTIVE_CHAIN_LENGTH,
    4,
    W.to_le_bytes()[0],
    W.to_le_bytes()[1],
    W.to_le_bytes()[2],
    W.to_le_bytes()[3],
    parameter::VERIFICATION_HORIZON,
    4,
    H.to_le_bytes()[0],
    H.to_le_bytes()[1],
    H.to_le_bytes()[2],
    H.to_le_bytes()[3],
    parameter::MAX_NODE_COUNT,
    4,
    (MAX_NODES as u32).to_le_bytes()[0],
    (MAX_NODES as u32).to_le_bytes()[1],
    (MAX_NODES as u32).to_le_bytes()[2],
    (MAX_NODES as u32).to_le_bytes()[3],
    parameter::SIGNATURE_SCHEME,
    1,
    moonblokz_crypto::SIGNATURE_SCHEME,
];

const NODE_ZERO_KEY: [u8; PRIVATE_KEY_SIZE] = [1; PRIVATE_KEY_SIZE];

/// `run` consumes its storage; the test keeps the backend outside it.
struct Shared<'a>(&'a RefCell<Backend>);

impl StorageTrait for Shared<'_> {
    fn init(
        &mut self,
        private_key: [u8; PRIVATE_KEY_SIZE],
        own_node_id: u32,
        init_params: [u8; INIT_PARAMS_SIZE],
    ) -> Result<(), StorageError> {
        self.0
            .borrow_mut()
            .init(private_key, own_node_id, init_params)
    }
    fn save_block(&mut self, index: StorageIndex, block: &Block) -> Result<(), StorageError> {
        self.0.borrow_mut().save_block(index, block)
    }
    fn read_block_into(
        &self,
        index: StorageIndex,
        out: &mut [u8; MAX_BLOCK_SIZE],
    ) -> Result<(), StorageError> {
        self.0.borrow().read_block_into(index, out)
    }
    fn capacity(&self) -> StorageIndex {
        self.0.borrow().capacity()
    }
    fn set_chain_configuration(&mut self, block: &Block) -> Result<(), StorageError> {
        self.0.borrow_mut().set_chain_configuration(block)
    }
    fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
        self.0.borrow_mut().load_control_data()
    }
}

// A logger that keeps each test thread's lines, so parallel tests do not mix.
std::thread_local! {
    static LINES: StdRefCell<Vec<String>> = const { StdRefCell::new(Vec::new()) };
}
struct Capture;
impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        LINES.with(|lines| lines.borrow_mut().push(record.args().to_string()));
    }
    fn flush(&self) {}
}
static CAPTURE: Capture = Capture;

fn take_lines() -> Vec<String> {
    let _ = log::set_logger(&CAPTURE);
    log::set_max_level(log::LevelFilter::Trace);
    LINES.with(|lines| core::mem::take(&mut *lines.borrow_mut()))
}

fn provisioned(node_id: u32, key: [u8; PRIVATE_KEY_SIZE]) -> RefCell<Backend> {
    let mut backend = Backend::new();
    backend
        .init(key, node_id, [0; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    RefCell::new(backend)
}

fn crypto(key: [u8; PRIVATE_KEY_SIZE]) -> Crypto {
    Crypto::new(key).ok().expect("a valid test key")
}

fn anchor() -> [u8; PUBLIC_KEY_SIZE] {
    *crypto(NODE_ZERO_KEY).public_key().serialize()
}

/// Boots one node on `storage`, delivers `commands`, and polls `run` until it
/// waits; returns the log lines it produced.
fn boot(
    storage: &RefCell<Backend>,
    node_id: u32,
    key: [u8; PRIVATE_KEY_SIZE],
    anchor: [u8; PUBLIC_KEY_SIZE],
    commands: &[LocalCommand],
) -> Vec<String> {
    take_lines();
    let channel = Channel::<NoopRawMutex, LocalCommand, 4>::new();
    for command in commands {
        let LocalCommand::Genesis { currency } = command;
        channel
            .try_send(LocalCommand::Genesis {
                currency: *currency,
            })
            .ok()
            .expect("room in the test channel");
    }
    let mut node: Pin<Box<_>> = Box::pin(run::<
        Crypto,
        Shared<'_>,
        NoopRawMutex,
        4,
        MAX_NODES,
        W,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        MAX_BLOCK_UTXO_OUTPUT,
    >(
        crypto(key),
        Shared(storage),
        node_id,
        anchor,
        7,
        &CONTENT,
        channel.receiver(),
    ));
    // The load-bearing yield, the boot, then one round per queued command.
    for _ in 0..commands.len() + 3 {
        assert!(poll_once(node.as_mut()).is_pending(), "run never returns");
    }
    drop(node);
    take_lines()
}

fn holds_genesis(storage: &RefCell<Backend>) -> bool {
    let backend = storage.borrow();
    backend.read_block(0).is_ok() && backend.read_block(1).is_ok()
}

fn has(lines: &[String], text: &str) -> bool {
    lines.iter().any(|line| line.contains(text))
}

#[test]
fn a_fresh_node_starts_collecting() {
    let storage = provisioned(3, [3; PRIVATE_KEY_SIZE]);
    let lines = boot(&storage, 3, [3; PRIVATE_KEY_SIZE], anchor(), &[]);
    assert!(has(&lines, "boot: StartedCollecting"), "{lines:?}");
}

#[test]
fn node_zero_founds_the_chain_on_genesis() {
    let storage = provisioned(0, NODE_ZERO_KEY);
    let lines = boot(
        &storage,
        0,
        NODE_ZERO_KEY,
        anchor(),
        &[LocalCommand::Genesis {
            currency: 1_000_000,
        }],
    );
    assert!(has(&lines, "boot: StartedCollecting"), "{lines:?}");
    assert!(has(&lines, "genesis: block #0"), "{lines:?}");
    assert!(holds_genesis(&storage));
}

#[test]
fn a_non_zero_node_refuses_genesis() {
    let storage = provisioned(3, [3; PRIVATE_KEY_SIZE]);
    let lines = boot(
        &storage,
        3,
        [3; PRIVATE_KEY_SIZE],
        anchor(),
        &[LocalCommand::Genesis {
            currency: 1_000_000,
        }],
    );
    assert!(has(&lines, "genesis refused: not node #0"), "{lines:?}");
    assert!(storage.borrow().read_block(0).is_err());
}

#[test]
fn a_key_that_is_not_the_anchor_founds_nothing() {
    let storage = provisioned(0, [2; PRIVATE_KEY_SIZE]);
    let lines = boot(
        &storage,
        0,
        [2; PRIVATE_KEY_SIZE],
        anchor(),
        &[LocalCommand::Genesis {
            currency: 1_000_000,
        }],
    );
    assert!(has(&lines, "genesis refused: KeyMismatch"), "{lines:?}");
    assert!(storage.borrow().read_block(0).is_err());
}

#[test]
fn a_restarted_node_zero_resumes_and_refuses_a_second_genesis() {
    let storage = provisioned(0, NODE_ZERO_KEY);
    boot(
        &storage,
        0,
        NODE_ZERO_KEY,
        anchor(),
        &[LocalCommand::Genesis {
            currency: 1_000_000,
        }],
    );
    let first = storage
        .borrow()
        .read_block(0)
        .ok()
        .expect("block #0")
        .hash();

    let lines = boot(
        &storage,
        0,
        NODE_ZERO_KEY,
        anchor(),
        &[LocalCommand::Genesis { currency: 5 }],
    );
    assert!(has(&lines, "boot: ResumedReady"), "{lines:?}");
    // The boot guard refuses before `process_genesis` is reached.
    assert!(
        has(
            &lines,
            "genesis refused: not node #0 booted on empty storage"
        ),
        "{lines:?}"
    );
    let after = storage
        .borrow()
        .read_block(0)
        .ok()
        .expect("block #0")
        .hash();
    assert_eq!(first, after, "the durable chain is untouched");
}

#[test]
fn next_call_at_resolves_at_its_deadline_and_idle_never_does() {
    let deadline = now_ms() + 100;
    let at = NextCall::At(deadline);
    let idle = NextCall::Idle;
    let mut timer = Box::pin(wait_until(&at));
    let mut never = Box::pin(wait_until(&idle));
    assert!(poll_once(timer.as_mut()).is_pending());
    MockDriver::get().advance(Duration::from_millis(100));
    assert_eq!(poll_once(timer.as_mut()), Poll::Ready(()));
    assert!(poll_once(never.as_mut()).is_pending());
}

// Silence the unused-import lint for the `Future` bound the pins rely on.
#[allow(dead_code)]
fn _assert_future<F: Future>(_: &F) {}

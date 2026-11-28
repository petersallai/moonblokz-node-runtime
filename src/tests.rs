//! Host tests for [`run`]: boot outcomes, the genesis guard, restart, and the
//! `NextCall` → timer mapping. Time is embassy-time's mock driver, so nothing
//! sleeps; `run` never returns, so a test polls it until its commands are
//! consumed and then drops it ("reboot" = drop and call `run` again on the same
//! storage). The storage is lent as `&mut`, the way the firmware lends it.

extern crate std;

use core::cell::RefCell;
use core::pin::pin;
use core::task::Poll;
use std::boxed::Box;
use std::string::{String, ToString};
use std::vec::Vec;

use embassy_futures::poll_once;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, MockDriver};
use moonblokz_chain_types::MAX_BLOCK_SIZE;
use moonblokz_configuration::parameter;
use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE, PublicKeyTrait};
use moonblokz_storage::{INIT_PARAMS_SIZE, MemoryBackend};

use super::*;

// The test chain: the blockchain suite's small profile.
const MAX_NODES: usize = 16;
const W: u32 = 16;
const H: u32 = 8;
const MAX_BLOCKS: usize = W as usize + 2 * H as usize;
const MAX_BRANCH_COUNT: usize = 4;
/// The production bitfield bytes (DEC-318).
const AVAILABLE_UTXO_BYTES: usize = 4;
/// A one-block mempool, the smallest the crate admits (DEC-351).
const MEMPOOL_COMPACT_BYTES: usize = MAX_BLOCK_SIZE;
const MEMPOOL_MAX_ENTRIES: usize = 16;
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

// A logger that keeps each test thread's lines, so parallel tests do not mix.
std::thread_local! {
    static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
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

fn provisioned(node_id: u32, key: [u8; PRIVATE_KEY_SIZE]) -> Box<Backend> {
    let mut backend = Box::new(Backend::new());
    backend
        .init(key, node_id, [0; INIT_PARAMS_SIZE])
        .ok()
        .expect("the test backend initializes");
    backend
}

fn crypto(key: [u8; PRIVATE_KEY_SIZE]) -> Crypto {
    Crypto::new(key).ok().expect("a valid test key")
}

fn anchor() -> [u8; PUBLIC_KEY_SIZE] {
    *crypto(NODE_ZERO_KEY).public_key().serialize()
}

/// Upper bound on polls; `run` waits within a handful once its channel is empty.
const MAX_POLLS: usize = 64;

/// Boots one node on `storage`, delivers `commands`, and polls `run` until every
/// command is consumed and it waits; returns the log lines it produced.
fn boot(
    storage: &mut Backend,
    node_id: u32,
    key: [u8; PRIVATE_KEY_SIZE],
    anchor: [u8; PUBLIC_KEY_SIZE],
    commands: &[u64],
) -> Vec<String> {
    take_lines();
    let channel = Channel::<NoopRawMutex, LocalCommand, 4>::new();
    for currency in commands {
        channel
            .try_send(LocalCommand::Genesis {
                currency: *currency,
            })
            .ok()
            .expect("room in the test channel");
    }
    {
        let mut node = pin!(run::<
            Crypto,
            &mut Backend,
            NoopRawMutex,
            4,
            MAX_NODES,
            W,
            MAX_BLOCKS,
            MAX_BRANCH_COUNT,
            AVAILABLE_UTXO_BYTES,
            MEMPOOL_COMPACT_BYTES,
            MEMPOOL_MAX_ENTRIES,
        >(
            crypto(key),
            storage,
            node_id,
            anchor,
            7,
            &CONTENT,
            channel.receiver(),
        ));
        // Past the load-bearing yield and the boot, until the commands are taken;
        // one more poll lets the last one finish.
        let mut polls = 0;
        loop {
            let _ = poll_once(node.as_mut());
            polls += 1;
            if channel.is_empty() || polls == MAX_POLLS {
                break;
            }
        }
        let _ = poll_once(node.as_mut());
        assert!(channel.is_empty(), "run did not consume its commands");
    }
    take_lines()
}

fn holds_genesis(storage: &Backend) -> bool {
    storage.read_block(0).is_ok() && storage.read_block(1).is_ok()
}

fn has(lines: &[String], text: &str) -> bool {
    lines.iter().any(|line| line.contains(text))
}

#[test]
fn a_fresh_node_starts_collecting() {
    let mut storage = provisioned(3, [3; PRIVATE_KEY_SIZE]);
    let lines = boot(&mut storage, 3, [3; PRIVATE_KEY_SIZE], anchor(), &[]);
    assert!(has(&lines, "boot: StartedCollecting"), "{lines:?}");
}

#[test]
fn node_zero_founds_the_chain_on_genesis() {
    let mut storage = provisioned(0, NODE_ZERO_KEY);
    let lines = boot(&mut storage, 0, NODE_ZERO_KEY, anchor(), &[1_000_000]);
    assert!(has(&lines, "boot: StartedCollecting"), "{lines:?}");
    assert!(has(&lines, "genesis: block #0"), "{lines:?}");
    assert!(holds_genesis(&storage));
}

#[test]
fn a_non_zero_node_refuses_genesis() {
    let mut storage = provisioned(3, [3; PRIVATE_KEY_SIZE]);
    let lines = boot(
        &mut storage,
        3,
        [3; PRIVATE_KEY_SIZE],
        anchor(),
        &[1_000_000],
    );
    assert!(has(&lines, "genesis refused: not node #0"), "{lines:?}");
    assert!(storage.read_block(0).is_err());
}

#[test]
fn a_key_that_is_not_the_anchor_founds_nothing() {
    let mut storage = provisioned(0, [2; PRIVATE_KEY_SIZE]);
    let lines = boot(
        &mut storage,
        0,
        [2; PRIVATE_KEY_SIZE],
        anchor(),
        &[1_000_000],
    );
    assert!(has(&lines, "genesis refused: KeyMismatch"), "{lines:?}");
    assert!(storage.read_block(0).is_err());
}

#[test]
fn a_restarted_node_zero_resumes_and_refuses_a_second_genesis() {
    let mut storage = provisioned(0, NODE_ZERO_KEY);
    boot(&mut storage, 0, NODE_ZERO_KEY, anchor(), &[1_000_000]);
    let first = storage.read_block(0).ok().expect("block #0").hash();

    let lines = boot(&mut storage, 0, NODE_ZERO_KEY, anchor(), &[5]);
    assert!(has(&lines, "boot: ResumedReady"), "{lines:?}");
    // The boot guard refuses before `process_genesis` is reached.
    assert!(
        has(
            &lines,
            "genesis refused: not node #0 booted on empty storage"
        ),
        "{lines:?}"
    );
    let after = storage.read_block(0).ok().expect("block #0").hash();
    assert_eq!(first, after, "the durable chain is untouched");
}

/// A chain stored under one anchor, booted by firmware baked with another: the
/// restart refuses the stored configuration and says what to do (DN1).
#[test]
fn a_firmware_that_does_not_match_the_stored_chain_says_so() {
    let mut storage = provisioned(0, NODE_ZERO_KEY);
    boot(&mut storage, 0, NODE_ZERO_KEY, anchor(), &[1_000_000]);
    let other_anchor = *crypto([2; PRIVATE_KEY_SIZE]).public_key().serialize();

    let lines = boot(&mut storage, 0, NODE_ZERO_KEY, other_anchor, &[]);
    assert!(
        has(&lines, "boot: Rejected(ChainConfigUnusable)"),
        "{lines:?}"
    );
    assert!(has(&lines, "flash the matching build"), "{lines:?}");
}

#[test]
fn next_call_at_resolves_at_its_deadline_and_idle_never_does() {
    let deadline = now_ms() + 100;
    let at = NextCall::At(deadline);
    let idle = NextCall::Idle;
    let mut timer = pin!(wait_until(&at));
    let mut never = pin!(wait_until(&idle));
    assert!(poll_once(timer.as_mut()).is_pending());
    MockDriver::get().advance(Duration::from_millis(100));
    assert_eq!(poll_once(timer.as_mut()), Poll::Ready(()));
    assert!(poll_once(never.as_mut()).is_pending());
}

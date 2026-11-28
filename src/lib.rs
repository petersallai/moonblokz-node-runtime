//! MoonBlokz node runtime: boots the blockchain and drives it on embassy.
//!
//! Hardware-independent (DEC-288): the board binary chooses the crypto and
//! storage backends, the capacity profile, the cores and the stacks, loads the
//! signing key from storage (a backend-inherent call no generic code can name,
//! DEC-267), and wraps [`run`] in its own `#[embassy_executor::task]`. The radio
//! simulator wraps the same function in its own task pool (Story 11.5).

#![no_std]
#![forbid(unsafe_code)]

use core::mem::MaybeUninit;

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Receiver;
use embassy_time::{Instant, Timer};
use moonblokz_blockchain::api::RestartRejectReason;
use moonblokz_blockchain::{Blockchain, GenesisRejectReason, InitOutcome, NextCall, TickOutcome};
use moonblokz_configuration::{ChainConfiguration, NoopConfigChangeSink};
use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE};
use moonblokz_storage::StorageTrait;

/// A command from the node's local interface (architecture §1.4 `local_api`).
pub enum LocalCommand {
    /// Found the chain on node #0 (FR54, DEC-292). Honored only when this node
    /// is node #0 and booted on empty storage.
    Genesis {
        /// `initial_total_network_currency`.
        currency: u64,
    },
}

/// Boots the blockchain and serves it forever.
///
/// Constructs the `Blockchain` in place, restores it with
/// `initialize_from_storage`, then waits on whichever comes first: the
/// blockchain's `NextCall` deadline (`on_tick`) or a local command.
///
/// **Placement (DEC-290).** The `Blockchain` is a local of this function and
/// stays alive across its suspend points, so it is a field of this future, and
/// through the caller's `#[embassy_executor::task]` it lives in that task's
/// static `TaskStorage`, not on a stack. `crypto` and `storage` are taken by
/// value; the board lends its storage as `&mut`, so the backend itself stays in
/// the board's task once (DEC-297), and measures what the copies cost (Story
/// 12.1 AC7).
#[allow(clippy::too_many_arguments)]
pub async fn run<
    C: CryptoTrait,
    S: StorageTrait,
    M: RawMutex,
    const Q: usize,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
>(
    crypto: C,
    storage: S,
    local_node_id: u32,
    node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
    prng_seed: u64,
    genesis_chain_config: &'static [u8],
    commands: Receiver<'_, M, LocalCommand, Q>,
) -> ! {
    type Chain<
        C,
        S,
        const N: usize,
        const W: u32,
        const B: usize,
        const R: usize,
        const U: usize,
        const MB: usize,
        const ME: usize,
    > = Blockchain<C, S, ChainConfiguration<NoopConfigChangeSink>, N, W, B, R, U, MB, ME>;

    let mut slot: MaybeUninit<
        Chain<
            C,
            S,
            MAX_NODES,
            SNAKE_CHAIN_LENGTH_MAX,
            MAX_BLOCKS,
            MAX_BRANCH_COUNT,
            AVAILABLE_UTXO_BYTES,
            MEMPOOL_COMPACT_BYTES,
            MEMPOOL_MAX_ENTRIES,
        >,
    > = MaybeUninit::uninit();
    let chain_config = ChainConfiguration::new(
        NoopConfigChangeSink,
        Chain::<
            C,
            S,
            MAX_NODES,
            SNAKE_CHAIN_LENGTH_MAX,
            MAX_BLOCKS,
            MAX_BRANCH_COUNT,
            AVAILABLE_UTXO_BYTES,
            MEMPOOL_COMPACT_BYTES,
            MEMPOOL_MAX_ENTRIES,
        >::BUILD_LIMITS,
    );
    let bc = Blockchain::init(
        &mut slot,
        crypto,
        storage,
        chain_config,
        local_node_id,
        node_zero_public_key,
        prng_seed,
    );

    // LOAD-BEARING AWAIT — do not "clean up" this line. Keeping `slot` alive
    // across a suspend point is what makes it a field of this future, i.e. of
    // the caller's static `TaskStorage`, instead of a ~100 KB transient on the
    // poll stack. No compiler warning catches its removal (DEC-290; the
    // in-place initialization design, MoonBlokz part X/2).
    embassy_futures::yield_now().await;

    let (started_collecting, mut next) = restore(bc);
    // `StartedCollecting` is the only proof that durable storage is empty;
    // `process_genesis` itself checks only in-memory state (DEC-292).
    let may_found_chain = local_node_id == 0 && started_collecting;

    loop {
        match select(wait_until(&next), commands.receive()).await {
            Either::First(()) => next = tick(bc),
            Either::Second(LocalCommand::Genesis { currency }) => {
                if !may_found_chain {
                    log::warn!("genesis refused: not node #0 booted on empty storage");
                    continue;
                }
                if let Some(after) = found_chain(bc, currency, genesis_chain_config) {
                    next = after;
                }
            }
        }
    }
}

// The blockchain calls run out of line (`restore`, `tick`, `found_chain`): what
// they keep on the stack is then popped when they return, instead of widening
// `run`'s poll frame, which stays under every later call (Story 12.1 AC7).

/// `initialize_from_storage`, logged; `true` when the node started collecting
/// on empty storage.
#[inline(never)]
fn restore<
    C: CryptoTrait,
    S: StorageTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
>(
    bc: &mut Blockchain<
        C,
        S,
        ChainConfiguration<NoopConfigChangeSink>,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        AVAILABLE_UTXO_BYTES,
        MEMPOOL_COMPACT_BYTES,
        MEMPOOL_MAX_ENTRIES,
    >,
) -> (bool, NextCall) {
    let (outcome, next) = bc.initialize_from_storage(now_ms());
    log_boot(&outcome);
    (matches!(outcome, InitOutcome::StartedCollecting), next)
}

/// Logs the boot outcome. Out of line, so its formatting temporaries do not
/// widen `restore`'s frame, which stays under the whole FR3 pass.
#[inline(never)]
fn log_boot(outcome: &InitOutcome) {
    let InitOutcome::Rejected(reason) = outcome else {
        log::info!("boot: {}", init_outcome_name(outcome));
        return;
    };
    // The node cannot serve a chain. Usually the firmware does not match the
    // stored chain (anchor, signature scheme, block-size tier, or a `MAX_NODES`
    // below the chain's node cap), and flashing the matching build recovers it
    // without erasing anything (Story 12.1 DN1).
    let hint = match reason {
        RestartRejectReason::ControlPlaneUnreadable => {
            "the storage failed while reading; check the flash, or erase the flash and re-provision"
        }
        RestartRejectReason::ChainConfigUnusable | RestartRejectReason::NoUsableTree => {
            "the stored chain does not match this firmware: flash the matching build (erasing the flash loses the chain)"
        }
        RestartRejectReason::AlreadyInitialized => {
            "internal: the blockchain was already initialized"
        }
    };
    log::error!("boot: {}; {}", init_outcome_name(outcome), hint);
}

/// `on_tick` at the deadline; returns the next one.
#[inline(never)]
fn tick<
    C: CryptoTrait,
    S: StorageTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
>(
    bc: &mut Blockchain<
        C,
        S,
        ChainConfiguration<NoopConfigChangeSink>,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        AVAILABLE_UTXO_BYTES,
        MEMPOOL_COMPACT_BYTES,
        MEMPOOL_MAX_ENTRIES,
    >,
) -> NextCall {
    let (outcome, next) = bc.on_tick(now_ms());
    // Exhaustive, so an added outcome is a compile error here.
    match outcome {
        TickOutcome::Idle => {}
        // The radio mapping (FR66) is a later Epic 12 story.
        TickOutcome::SendParentRecoveryRequest(_) => {
            log::debug!("tick: parent-recovery request (radio not wired; dropped)")
        }
    }
    next
}

/// Runs node #0's genesis and returns the first `NextCall` on success.
///
/// Out of line on purpose: the two genesis blocks (about 2 KB each) then live in
/// this frame, which is popped before the next call into the blockchain,
/// instead of in `run`'s poll frame, which stays under every later call
/// (Story 12.1 AC7).
#[inline(never)]
fn found_chain<
    C: CryptoTrait,
    S: StorageTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
>(
    bc: &mut Blockchain<
        C,
        S,
        ChainConfiguration<NoopConfigChangeSink>,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        AVAILABLE_UTXO_BYTES,
        MEMPOOL_COMPACT_BYTES,
        MEMPOOL_MAX_ENTRIES,
    >,
    currency: u64,
    genesis_chain_config: &[u8],
) -> Option<NextCall> {
    match bc.process_genesis(currency, genesis_chain_config) {
        Ok(blocks) => {
            log::info!(
                "genesis: block #0 {:02x?}, block #1 {:02x?}",
                blocks.block_zero.hash(),
                blocks.block_one.hash()
            );
            // Genesis returns no `NextCall`; ask for the first one.
            Some(tick(bc))
        }
        Err(reason) => {
            log::warn!("genesis refused: {}", genesis_reject_name(&reason));
            None
        }
    }
}

/// Local monotonic milliseconds since boot (architecture §1.5).
fn now_ms() -> u64 {
    Instant::now().as_millis()
}

/// Resolves at the `NextCall` deadline; never resolves on `Idle`.
async fn wait_until(next: &NextCall) {
    match next {
        NextCall::At(at) => Timer::at(Instant::from_millis(*at)).await,
        NextCall::Idle => core::future::pending().await,
    }
}

// The outcome enums carry no `Debug` in production (§0), so they are named by
// hand; an added variant is a compile error here.
fn init_outcome_name(outcome: &InitOutcome) -> &'static str {
    match outcome {
        InitOutcome::StartedCollecting => "StartedCollecting",
        InitOutcome::ResumedReady => "ResumedReady",
        InitOutcome::ResumedCollecting => "ResumedCollecting",
        InitOutcome::Rejected(RestartRejectReason::ControlPlaneUnreadable) => {
            "Rejected(ControlPlaneUnreadable)"
        }
        InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable) => {
            "Rejected(ChainConfigUnusable)"
        }
        InitOutcome::Rejected(RestartRejectReason::NoUsableTree) => "Rejected(NoUsableTree)",
        InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized) => {
            "Rejected(AlreadyInitialized)"
        }
    }
}

fn genesis_reject_name(reason: &GenesisRejectReason) -> &'static str {
    match reason {
        GenesisRejectReason::LocalNodeIdNotZero => "LocalNodeIdNotZero",
        GenesisRejectReason::StorageNotEmpty => "StorageNotEmpty",
        GenesisRejectReason::InitialChainConfigTooLarge => "InitialChainConfigTooLarge",
        GenesisRejectReason::InitialChainConfigRejected => "InitialChainConfigRejected",
        GenesisRejectReason::StorageSaveFailed => "StorageSaveFailed",
        GenesisRejectReason::StorageNotInitialized => "StorageNotInitialized",
        GenesisRejectReason::GenesisBlockExceedsBlockSizeLimit => {
            "GenesisBlockExceedsBlockSizeLimit"
        }
        GenesisRejectReason::KeyMismatch => "KeyMismatch",
    }
}

#[cfg(test)]
mod tests;

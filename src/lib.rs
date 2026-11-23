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
/// static `TaskStorage`, not on a stack. `crypto` and `storage` are moved in by
/// value; the board measures what that costs (Story 12.1 AC7).
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
    const MAX_BLOCK_UTXO_OUTPUT: usize,
>(
    crypto: C,
    storage: S,
    local_node_id: u32,
    node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
    prng_seed: u64,
    genesis_chain_config: &'static [u8],
    commands: Receiver<'_, M, LocalCommand, Q>,
) -> ! {
    type Chain<C, S, const N: usize, const W: u32, const B: usize, const R: usize, const U: usize> =
        Blockchain<C, S, ChainConfiguration<NoopConfigChangeSink>, N, W, B, R, U>;

    let mut slot: MaybeUninit<
        Chain<
            C,
            S,
            MAX_NODES,
            SNAKE_CHAIN_LENGTH_MAX,
            MAX_BLOCKS,
            MAX_BRANCH_COUNT,
            MAX_BLOCK_UTXO_OUTPUT,
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
            MAX_BLOCK_UTXO_OUTPUT,
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

    let (outcome, mut next) = bc.initialize_from_storage(now_ms());
    log::info!("boot: {}", init_outcome_name(&outcome));
    // `StartedCollecting` is the only proof that durable storage is empty;
    // `process_genesis` itself checks only in-memory state (DEC-292).
    let may_found_chain = local_node_id == 0 && matches!(outcome, InitOutcome::StartedCollecting);

    loop {
        match select(wait_until(&next), commands.receive()).await {
            Either::First(()) => {
                let (tick, after) = bc.on_tick(now_ms());
                if let TickOutcome::SendParentRecoveryRequest(_) = tick {
                    // The radio mapping (FR66) is a later Epic 12 story.
                    log::debug!("tick: parent-recovery request (radio not wired; dropped)");
                }
                next = after;
            }
            Either::Second(LocalCommand::Genesis { currency }) => {
                if !may_found_chain {
                    log::warn!("genesis refused: not node #0 booted on empty storage");
                    continue;
                }
                match bc.process_genesis(currency, genesis_chain_config) {
                    Ok(blocks) => {
                        log::info!(
                            "genesis: block #0 {:02x?}, block #1 {:02x?}",
                            blocks.block_zero.hash(),
                            blocks.block_one.hash()
                        );
                        // Genesis returns no `NextCall`; ask for the first one.
                        next = bc.on_tick(now_ms()).1;
                    }
                    Err(reason) => log::warn!("genesis refused: {}", genesis_reject_name(&reason)),
                }
            }
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

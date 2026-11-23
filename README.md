# moonblokz-node-runtime

Hardware-independent MoonBlokz node runtime: boots the blockchain and drives it on embassy, for the RP2040 firmware (`moonblokz-node-rp2040`) and the radio simulator alike (DEC-288).

- `no_std`, no-alloc, no `unsafe`; depends on `embassy-time` / `embassy-sync` / `embassy-futures` only — no executor, no HAL.
- One generic entry point, `run`: constructs the `Blockchain` in place inside the calling task's future (DEC-290), restores it from storage, and serves the `NextCall` timer and local commands (today `Genesis`, DEC-292).
- The board binary chooses the crypto and storage backends, the capacity profile, the cores and the stacks, loads the signing key from storage, and wraps `run` in its own task.
- Not yet: the radio ↔ blockchain mapping (FR66), a later Epic 12 story.

Implementation tracked story-by-story in `_bmad-output/implementation-artifacts/sprint-status.yaml`.

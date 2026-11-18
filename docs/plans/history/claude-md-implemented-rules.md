# CLAUDE.md: implemented rules

Parts of the project rules (`CLAUDE.md`) whose work is implemented: the P09 to P07 to P10 sequencing, the 2026-11-04 restoration of P07 and the rules of the Yggdrasil adapter, and the note on the architectural draft. They were moved here verbatim on 2026-11-18 at the owner's request ("перенесем в архивную папку то, что уже реализовали - чтобы не мешало контексту"). The standing rules that they repeat live in the numbered sections of `CLAUDE.md` and in the north star.

## From V1 execution focus

- Finish existing P09 acceptance before opening new product work, proof mechanisms,
  or CI segments; only a specific uncovered failing case justifies an exception.
  After P09 acceptance, complete permission-gated P07 (#224/#33/#34), then start
  existing P10 #214. Do not open P07 in parallel with unfinished P09.
- Decision history: on 2026-11-04 the user restored P07/Yggdrasil to v1,
  superseding the 2026-10-31 deferral. P10, P13 and P16 require accepted P07.
  Preserve one Ed25519 identity, native QUIC priority and strict signaling-only
  libp2p. Yggdrasil is an explicit negotiation/standby path; libp2p relay never
  carries application data.
- P07 uses an isolated safe Rust adapter over the reviewed pinned external core:
  no unsafe, Go, FFI, TUN, root or route changes. Integration and public-peer
  execution need their separate permissions; returning P07 to scope opens neither.
  Record acceptance/non-goals before P07. The user separately approved pinned
  integration after P09 and made controlled blockade resilience mandatory on
  2026-11-04; public smoke is conditional on agreed exact peers and enforceable
  budgets in `docs/plans/v1-focus.md`. Torrent-style file exchange remains future work.

## Consequence for the architectural draft

`docs/architecture/keypipe.md` is an architectural draft. Its Go shim for
Yggdrasil is superseded by the native Rust backend decision
(Yggdrasil-ng): integration with the native Yggdrasil core is done as an
isolated Rust adapter meeting the same isolation and safety requirements.
Historical Go-FFI sketches remain superseded reference; sketches do not
exempt one from verifying isolation invariants or from the other rules.

======================================================================
ADR-002: Phase 2 Pre-Hashed Ed25519ph Streaming and Guarded Subkey KDF
======================================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: Core Shard Architecture Team

Context
-------

Single-pass ``Ed25519`` signing (``crypto_sign_detached``) requires the entire message buffer to reside contiguously in memory, which is unsuitable for multi-gigabyte artifacts or streaming network payloads. Furthermore, applications managing hierarchical cryptographic keys require deterministic subkey derivation from a single guarded master key without exposing intermediate key material to the Crystal garbage collector heap, alongside comprehensive edge-case vector validation against small-order curve points and malleable signatures.

Decision
--------

#. **Guarded Ed25519ph Streaming State**: Implement ``[FUNC-006]`` and ``[TECH-006]`` for Phase 2 (``v0.2.2``) using ``libsodium``'s RFC 8032 Section 5.1 pre-hashed ``crypto_sign_ed25519ph_state`` (208 bytes) allocated directly inside ``sodium_malloc`` guarded memory. Each ``#update`` transition acquires ``@mutex.synchronize``, unlocks the guarded state page via ``sodium_mprotect_readwrite``, updates the SHA-512 state, and restores ``sodium_mprotect_readonly``. Both ``#final_sign`` and ``#final_verify`` acquire ``@mutex.synchronize``, unlock the guarded 208-byte ``CryptoSignEd25519phState`` page via ``sodium_mprotect_readwrite`` prior to invoking ``crypto_sign_ed25519ph_final_create`` or ``crypto_sign_ed25519ph_final_verify`` (because ``libsodium`` finalizes ``state->hs`` in place), and deterministically zero (``sodium_memzero``) and free (``sodium_free``) the state buffer inside an ``ensure`` block.
#. **Guarded BLAKE2b Subkey Derivation**: Implement ``[FUNC-007]`` and ``[TECH-007]`` for Phase 2 (``v0.2.2``) by binding ``crypto_kdf_derive_from_key`` and writing derived subkeys (16 to 64 bytes) directly into newly allocated ``SecureBuffer`` instances locked with ``sodium_mprotect_readonly``. Invalid ``master_key.size`` (``!= 32``), ``context.bytesize`` (``!= 8``), or ``subkey_size`` (``< 16`` or ``> 64``) raises ``ArgumentError``, while a disposed ``master_key`` or non-zero ``crypto_kdf_derive_from_key`` return code raises ``SodiumError``.
#. **RFC and Wycheproof Edge-Case Vector Harness**: Integrate an automated test vector suite verifying RFC 8032, RFC 7748, and Project Wycheproof vectors to assert rejection of small-order X25519 points, non-canonical Ed25519 points, and malleable ``S >= L`` signature scalars (``[TECH-005]``, ``[TECH-007]``).

Consequences
------------

* **Positive**: Multi-part streaming signatures and derived subkeys maintain 100% isolation from the Crystal GC heap with hardware page protection, and edge-case curve attacks are continuously verified in CI.
* **Negative**: ``Ed25519ph`` signatures are domain-separated per RFC 8032 and are intentionally incompatible with standard single-pass ``Ed25519`` verifiers unless verified via ``crypto_sign_ed25519ph_final_verify``.

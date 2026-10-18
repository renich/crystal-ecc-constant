=================
Core Requirements
=================

Traceability Summary
--------------------

.. list-table::
   :widths: 16 38 32 14
   :header-rows: 1

   * - Requirement ID
     - Capability Title
     - Technical Specs
     - Target Release
   * - ``[FUNC-001]``
     - Guarded Memory Secret Isolation
     - :doc:`../../technical/specs/architecture-overview` (``[TECH-001]``), :doc:`../../technical/specs/threat-model` (``[TECH-005]``)
     - ``v0.2.1``
   * - ``[FUNC-002]``
     - Constant-Time Ed25519 Digital Signatures
     - :doc:`../../technical/specs/architecture-overview` (``[TECH-002]``), :doc:`../../technical/specs/threat-model` (``[TECH-005]``)
     - ``v0.2.1``
   * - ``[FUNC-003]``
     - Constant-Time X25519 ECDH Key Agreement
     - :doc:`../../technical/specs/architecture-overview` (``[TECH-002]``, ``[TECH-003]``), :doc:`../../technical/specs/threat-model` (``[TECH-005]``)
     - ``v0.2.1``
   * - ``[FUNC-004]``
     - Constant-Time Byte Comparison
     - :doc:`../../technical/specs/coding-standards` (``[TECH-004]``)
     - ``v0.2.1``
   * - ``[FUNC-005]``
     - Thread-Safe Concurrent Execution
     - :doc:`../../technical/specs/architecture-overview` (``[TECH-001]``), :doc:`../../technical/specs/coding-standards` (``[TECH-004]``), :doc:`../../technical/specs/release-procedure`
     - ``v0.2.1``
   * - ``[FUNC-006]``
     - Pre-Hashed Ed25519ph Streaming Signatures
     - :doc:`../../technical/specs/architecture-overview` (``[TECH-006]``)
     - ``v0.2.2``
   * - ``[FUNC-007]``
     - Guarded Subkey Derivation and Wycheproof Vector Verification
     - :doc:`../../technical/specs/threat-model` (``[TECH-005]``), :doc:`../../technical/specs/architecture-overview` (``[TECH-007]``)
     - ``v0.2.2``

Functional Requirements
-----------------------

* **[FUNC-001] Guarded Memory Secret Isolation**:
  The library must isolate all secret key material inside ``libsodium`` guarded memory via ``SecureBuffer`` and ``PrivateKeyPointer``. Allocations must invoke ``sodium_malloc`` to pin pages in physical memory with surrounding canary and guard pages, transition immediately to read-only hardware page permissions via ``sodium_mprotect_readonly`` after population, synchronize all pointer access and state transitions under ``Sync::Mutex``, and deterministically wipe memory via ``sodium_mprotect_readwrite``, ``sodium_memzero``, and ``sodium_free`` upon disposal.

* **[FUNC-002] Constant-Time Ed25519 Digital Signatures**:
  The library must provide constant-time Ed25519 keypair generation (``Ed25519KeyPair.generate``), deterministic 32-byte seed derivation (``Ed25519KeyPair.from_seed``), 64-byte detached signature generation (``Ed25519KeyPair#sign``), and constant-time detached verification (``Ed25519KeyPair#verify``, ``Ed25519KeyPair.verify_detached``, ``PublicKey#verify_ed25519``, and ``Sodium.verify_ed25519``). Invalid seed lengths (``!= 32`` bytes) or signature lengths (``!= 64`` bytes) must raise ``ArgumentError``, and operations on disposed keys must raise ``SodiumError``.

* **[FUNC-003] Constant-Time X25519 ECDH Key Agreement**:
  The library must provide constant-time X25519 keypair generation (``X25519KeyPair.generate``), deterministic 32-byte seed derivation (``X25519KeyPair.from_seed``), and Curve25519 scalar multiplication (``X25519KeyPair#shared_secret`` and ``X25519KeyPair#diffie_hellman``) returning a single-use ``SharedSecret`` allocated in guarded memory. Small-order or all-zero peer public keys must be rejected by raising ``SodiumError`` and immediately disposing the target buffer. ``SharedSecret#consume`` must enforce single-use semantics with automatic deterministic zeroization and disposal via ``ensure``.

* **[FUNC-004] Constant-Time Byte Comparison**:
  The library must provide ``Sodium.constant_time_equal?`` backed by ``sodium_memcmp`` to compare byte slices in constant time without data-dependent branching. Comparing two empty byte slices must return ``true`` without passing null pointers across FFI boundaries, and comparing slices of unequal length must return ``false``. ``PublicKey#==`` and ``Signature#==`` must delegate equality checks to ``Sodium.constant_time_equal?``.

* **[FUNC-005] Thread-Safe Concurrent Execution**:
  The library must guarantee thread-safe initialization and concurrent cryptographic execution across Crystal 1.21 ``Fiber::ExecutionContext::Parallel`` worker threads. ``Sodium.init`` must use double-checked locking with ``Atomic(Bool)`` and ``Sync::Mutex`` and enforce a runtime version gate requiring ``sodium_library_version_major >= 10``. All guarded memory handles must synchronize FFI execution and disposal spans under ``Sync::Mutex`` to prevent time-of-check to time-of-use race conditions, and all build, test, SAST, and documentation targets must execute deterministically via ``GNUmakefile``.

* **[FUNC-006] Pre-Hashed Ed25519ph Streaming Signatures**:
  For Phase 2 (``v0.2.2``), the library must implement RFC 8032 Section 5.1 pre-hashed ``Ed25519ph`` multi-part streaming signatures using ``crypto_sign_ed25519ph_state`` allocated inside ``sodium_malloc`` guarded memory. The streaming signer must support incremental chunk ingestion (``crypto_sign_ed25519ph_update``), deterministic finalization into a 64-byte ``Signature`` (``crypto_sign_ed25519ph_final_create``), streaming verification (``crypto_sign_ed25519ph_final_verify``), and immediate ``sodium_memzero`` state wiping under ``Sync::Mutex``.

* **[FUNC-007] Guarded Subkey Derivation and Wycheproof Vector Verification**:
  For Phase 2 (``v0.2.2``), the library must implement BLAKE2b-based hierarchical subkey derivation via ``crypto_kdf_derive_from_key`` accepting a 32-byte guarded master key, a 64-bit ``subkey_id``, and an 8-byte ``context`` string, returning isolated subkeys between 16 and 64 bytes directly inside ``SecureBuffer`` guarded memory without touching the Crystal GC heap. Supplying an invalid ``master_key.size`` (``!= 32``), ``context.bytesize`` (``!= 8``), or ``subkey_size`` (``< 16`` or ``> 64``) must raise ``ArgumentError``, whereas a disposed ``master_key`` or a non-zero ``crypto_kdf_derive_from_key`` return code must raise ``SodiumError``. In addition, the verification suite must execute automated RFC 8032, RFC 7748, and Project Wycheproof edge-case test vectors covering small-order points, non-canonical encodings, and malleable signatures.

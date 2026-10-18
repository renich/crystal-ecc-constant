============
Threat Model
============

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-007]``.

Technical Specification
-----------------------

* **[TECH-005] Cryptographic Threat Mitigation and Adversarial Defenses** (Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-007]``):
  The library enforces layered defenses against timing side channels, garbage collector heap remanence, virtual memory swapping, concurrent Use-After-Free races, small-order X25519 curve points, and Ed25519 signature malleability.

Security Posture
----------------

* **Timing Side-Channel Mitigation**:
  All scalar multiplications, field arithmetic, signature generation, verification, subkey derivation, and byte comparisons execute through ``libsodium`` constant-time routines without secret-dependent branches or table lookups. ``Sodium.constant_time_equal?`` uses ``sodium_memcmp`` to prevent byte-by-byte timing oracle attacks.

* **GC Heap Remanence and Swap Isolation**:
  All private keys (``SecureBuffer`` and ``PrivateKeyPointer``), unconsumed ECDH shared secrets (``SharedSecret``), ``Ed25519ph`` streaming states, and derived subkeys are allocated in ``libsodium``'s ``sodium_malloc`` arena. Pages are pinned in physical RAM via ``mlock``, surrounded by unmapped guard pages and canary bytes, and excluded from core dumps and Crystal GC heap compaction.

* **Hardware Page Protection**:
  Secret memory regions are locked read-only via ``sodium_mprotect_readonly`` immediately after initialization and unlocked via ``sodium_mprotect_readwrite`` exclusively under ``Sync::Mutex`` lock immediately prior to ``sodium_memzero`` zeroization and ``sodium_free`` deallocation.

* **Small-Order X25519 Point Rejection**:
  ``X25519KeyPair#diffie_hellman`` and ``#shared_secret`` check the return code of ``LibSodium.crypto_scalarmult``. When a peer supplies an all-zero or small-order Curve25519 public key that produces an all-zero shared secret point at infinity, ``crypto_scalarmult`` returns ``-1``, and the library immediately wipes and frees the target ``SharedSecret`` buffer before raising ``SodiumError``.

* **Ed25519 Signature Malleability Rejection**:
  ``PublicKey#verify_ed25519`` and ``Ed25519KeyPair.verify_detached`` delegate to ``LibSodium.crypto_sign_verify_detached``, which enforces strict RFC 8032 canonical scalar validation (rejecting signatures where ``S >= L`` or where ``R`` is a non-canonical or small-order Edwards point), verified continuously against Project Wycheproof edge-case vectors.

* **Concurrency and Double-Free Prevention**:
  Secret-bearing handles use ``class`` reference semantics rather than value structs to prevent implicit pointer duplication on assignment, and ``Sync::Mutex`` guards the entire FFI execution and consumption span to eliminate TOCTOU Use-After-Free race conditions.

============
Threat Model
============

Requirement Mapping
-------------------

Fulfills ``[FUNC-003]``, ``[FUNC-004]``.

Security Posture
----------------

* **Garbage Collector Isolation**: All private keys (``PrivateKeyPointer``) and unconsumed ECDH shared secrets (``SharedSecret``) are allocated in ``libsodium``'s ``sodium_malloc`` arena (pinned via ``mlock`` and fenced by guard pages), preventing the Crystal GC from copying or leaving residual secret scalars in heap memory.
* **Hardware Page Protection**: Secret memory regions are locked read-only via ``sodium_mprotect_readonly`` immediately after initialization and unlocked via ``sodium_mprotect_readwrite`` only under mutex lock immediately prior to ``sodium_memzero`` zeroization and ``sodium_free`` deallocation.
* **Concurrency and Use-After-Free Prevention**: ``PrivateKeyPointer#with_pointer`` and ``SharedSecret#consume`` hold ``Sync::Mutex`` across the entire FFI execution or consumption span, preventing TOCTOU Use-After-Free races if ``dispose`` is invoked concurrently on another fiber.
* **Double-Free Prevention**: Secret-bearing handles use ``class`` reference semantics rather than value structs, preventing implicit pointer duplication on variable assignment.
* **Side-Channel Mitigation**: All curve operations delegate to ``libsodium`` constant-time implementations, weak all-zero X25519 peer public keys are rejected, and ``Sodium.constant_time_equal?`` uses ``sodium_memcmp`` for timing-safe comparisons.

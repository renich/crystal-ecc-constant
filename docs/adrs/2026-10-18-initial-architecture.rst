================================================================
ADR-001: libsodium Secure Memory Isolation and Reference Handles
================================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: Core Shard Architecture Team

Context
-------

Cryptographic private keys and ECDH shared secrets managed on Crystal's garbage-collected heap are vulnerable to GC copying, unpinned memory swapping, and residual heap persistence. Conversely, wrapping raw C pointers inside stack-allocated Crystal ``struct`` value types risks silent pointer duplication on assignment and subsequent double-free vulnerabilities, while unsynchronized multi-fiber access risks time-of-check to time-of-use Use-After-Free bugs.

Decision
--------

#. **libsodium Secure Memory Arena**: Allocate all Ed25519 private keys, X25519 private scalars, and X25519 shared secrets using ``sodium_malloc``, locking pages read-only via ``sodium_mprotect_readonly`` after initialization and wiping via ``sodium_memzero`` before ``sodium_free``.
#. **Reference Semantics for Secret Handles**: Implement ``PrivateKeyPointer``, ``Ed25519KeyPair``, ``X25519KeyPair``, and ``SharedSecret`` as heap-allocated ``class`` reference types synchronized by ``Sync::Mutex`` across the entire FFI execution and consumption span.
#. **Immutable Value Structs for Public Artifacts**: Implement ``PublicKey`` and ``Signature`` as immutable ``struct`` value types that return defensive byte copies on public accessors while using ``protected def raw_bytes`` internally.

Consequences
------------

* **Positive**: Zero secret material resides on the Crystal GC heap; hardware guard pages and read-only page permissions protect secrets at rest; double-free and TOCTOU Use-After-Free race conditions are eliminated under Crystal 1.21 multithreaded execution contexts.
* **Negative**: Callers must link against system ``libsodium`` (major version ``>= 10``) and should invoke ``#dispose`` deterministically when finished with keypairs or unconsumed shared secrets.

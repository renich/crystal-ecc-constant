=================
Problem Statement
=================

Context
-------

Garbage-collected languages like Crystal routinely allocate byte buffers on the managed GC heap. When private cryptographic scalars or ECDH shared secrets are stored in standard GC-managed slices, the collector may scan, copy, or leave residual copies of secret material in unpinned memory pages that can be swapped to disk or exposed via memory disclosure vulnerabilities. Additionally, naive struct wrappers around raw pointers risk double-free bugs when copied by value, while unsynchronized multi-fiber disposal introduces time-of-check to time-of-use race conditions.

Solution
--------

``crystal-ecc-constant`` provides a constant-time Elliptic Curve Cryptography library for Ed25519 digital signatures and X25519 Diffie-Hellman key agreement that completely isolates secret material inside ``libsodium``'s ``sodium_malloc`` secure memory arena. Secret buffers are pinned in physical memory, guarded by canary pages, locked read-only via ``sodium_mprotect_readonly`` when at rest, synchronized with ``Sync::Mutex`` across all FFI operations, and deterministically wiped via ``sodium_memzero`` prior to deallocation.

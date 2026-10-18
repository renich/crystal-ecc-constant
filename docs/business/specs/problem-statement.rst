=================
Problem Statement
=================

Context
-------

Garbage-collected languages like Crystal allocate standard byte buffers on the managed GC heap. When private cryptographic scalars, streaming hash states, or ECDH shared secrets reside in GC-managed slices, the collector scans, relocates, and retains residual copies of secret material in unpinned memory pages that the operating system swaps to disk or exposes through memory disclosure vulnerabilities. Furthermore, naive value-struct wrappers around raw pointers introduce double-free bugs when copied by value, while unsynchronized multi-fiber disposal introduces time-of-check to time-of-use race conditions across parallel execution contexts.

Solution
--------

``crystal-ecc-constant`` delivers a strictly constant-time Elliptic Curve Cryptography library for Ed25519 digital signatures, pre-hashed ``Ed25519ph`` streaming signatures, X25519 Diffie-Hellman key agreement, and guarded subkey derivation that isolates all secret material inside ``libsodium``'s ``sodium_malloc`` secure memory arena. Secret buffers are pinned in physical memory via ``mlock``, fenced by guard pages, locked read-only via ``sodium_mprotect_readonly`` when at rest, synchronized with ``Sync::Mutex`` across all FFI operations, and deterministically wiped via ``sodium_memzero`` prior to ``sodium_free`` deallocation.

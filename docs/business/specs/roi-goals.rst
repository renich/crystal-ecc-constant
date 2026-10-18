===================
ROI and Key Metrics
===================

Measurable Objectives
---------------------

#. **Complete GC Secret Isolation**: Enforce 100% isolation of private keys, unconsumed shared secrets, ``Ed25519ph`` streaming states, and derived subkeys inside ``sodium_malloc`` guard-paged memory outside the Crystal garbage collector heap.
#. **Hardware Page Protection**: Enforce ``sodium_mprotect_readonly`` on all secret buffers immediately after initialization, unlocking with ``sodium_mprotect_readwrite`` exclusively during deterministic ``sodium_memzero`` disposal or state transitions.
#. **Concurrency and Memory Safety**: Guarantee zero double-free and zero Use-After-Free vulnerabilities under Crystal 1.21 ``Fiber::ExecutionContext::Parallel`` through reference-semantic class handles and ``Sync::Mutex`` FFI synchronization.
#. **Cryptographic Vector Verification**: Maintain 100% pass rates across unit specs, multi-fiber concurrency tests, RFC 8032 and RFC 7748 test vectors, Wycheproof edge-case vectors, Ameba static analysis, Flaw security scanning, and ``crstlint`` documentation checks.

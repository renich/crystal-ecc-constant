===================
ROI and Key Metrics
===================

Measurable Objectives
---------------------

#. **Complete GC Secret Isolation**: Ensure 100% of private keys and unconsumed shared secrets reside in ``sodium_malloc`` guard-paged memory outside the Crystal garbage collector heap.
#. **Hardware Page Protection**: Enforce ``sodium_mprotect_readonly`` on all secret buffers immediately after initialization, unlocking with ``sodium_mprotect_readwrite`` only during deterministic ``sodium_memzero`` disposal.
#. **Concurrency and Memory Safety**: Guarantee zero double-free or Use-After-Free vulnerabilities under Crystal 1.21 parallel execution contexts through reference-semantic class handles and ``Sync::Mutex`` FFI synchronization.
#. **Zero Initial Defects**: Maintain 100% pass rates across unit and adversarial specs, Ameba static analysis, Flaw security scanning, and ``crstlint`` documentation checks.

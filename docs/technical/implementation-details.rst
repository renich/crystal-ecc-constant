Implementation Details
======================

Implementation Highlights
-------------------------

* Thread-safe initialization utilizing double-checked locking.
* Runtime version check ensuring ``libsodium`` version is at least 1.0.18.
* Proper utilization of FFI types, explicitly using ``UInt64`` for size parameters.
* Reference counting thoroughly prevents double-free vulnerabilities while natively allowing multiple references.

Testing Requirements
--------------------

Before production deployment, the module rigorously requires:

* **Unit tests**: Coverage for every public function.
* **Fuzzing**: Malformed inputs using tools like AFL++ and libFuzzer.
* **Integration tests**: Real TPM, real D-Bus daemon.
* **Constant-time verification**: Utilizing dudect and ctgrind.
* **Security audit**: A complete third-party review.

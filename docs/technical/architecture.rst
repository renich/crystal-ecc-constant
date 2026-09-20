Architecture
============

The ``crystal-ecc-constant`` module provides a robust architecture for cryptography, focusing strictly on memory isolation, avoiding Garbage Collector (GC) pointer scanning, and securely utilizing ``libsodium``.

Memory Isolation and GC Safety
------------------------------

To prevent the Crystal Garbage Collector from scanning secure pointers and to avoid unintended memory leaks or double-free issues, the library enforces strict memory isolation.

Key Design Decisions
~~~~~~~~~~~~~~~~~~~~

* Use ``struct`` wrappers (e.g., ``PrivateKeyPointer``, ``PublicKey``, ``Signature``) instead of classes to prevent GC scanning of pointers.
* Explicit memory disposal via ``dispose`` methods on keypairs and shared secrets.
* ``PublicKey#to_bytes`` and ``Signature#to_bytes`` always return a copy of the bytes to prevent accidental mutation.

Core Cryptographic Modules
--------------------------

Ed25519 and X25519
~~~~~~~~~~~~~~~~~~

* **Ed25519**: Implements ``Ed25519KeyPair`` for generation and signing. Signing operations are protected by a ``CRYPTO_MUTEX`` for concurrency safety.
* **X25519**: Implements ``X25519KeyPair`` for generation and ECDH (``diffie_hellman``).
* **SharedSecret**: A wrapper for the ECDH shared secret that strictly enforces a single-use policy by throwing an error on the second call to ``consume``.

Initialization and Security
---------------------------

* **Double-Checked Locking**: The ``Sodium.init`` method utilizes double-checked locking for thread-safe initialization.
* **Version Enforcement**: A minimum version of ``libsodium`` is enforced at initialization.
* **Constant-Time Utilities**: Includes a ``Sodium.constant_time_equal?`` method to prevent timing attacks.

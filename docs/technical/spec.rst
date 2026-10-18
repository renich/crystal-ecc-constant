==========================================
Crystal Sodium FFI Technical Specification
==========================================

:Version: 0.1.2
:Status: Active
:Target: Secure FFI wrapper to libsodium with guaranteed memory isolation

Overview
========

This document specifies a Crystal FFI binding to ``libsodium`` that provides
constant-time elliptic curve cryptography with **guaranteed memory isolation**
from Crystal's garbage collector.

**Security Model**: All private key and shared secret material is allocated in
libsodium's secure memory arena (``mlock``-pinned, ``mprotect``-guarded, and
fenced with canary and guard pages), completely outside Crystal's managed heap.
The Crystal GC never scans, moves, or copies secret scalars.

Scope
=====

In Scope
--------

* Ed25519: detached sign, verify, random keypair generation, deterministic seed derivation
* X25519: Curve25519 ECDH scalar multiplication, random keypair generation, deterministic seed derivation
* Constant-time comparison: ``sodium_memcmp``
* Secure memory: ``sodium_malloc`` and ``sodium_free`` with ``sodium_mprotect_*`` and ``sodium_memzero``

Out of Scope
------------

* Native Crystal ECC scalar arithmetic implementations
* Symmetric encryption primitives
* Password hashing primitives

Security Architecture
=====================

Memory Isolation Model
----------------------

All sensitive buffers are allocated inside libsodium's secure memory arena while
Crystal manages lightweight ``class`` reference handles synchronized by
``Sync::Mutex``. Using ``class`` reference semantics for ``PrivateKeyPointer``,
``Ed25519KeyPair``, ``X25519KeyPair``, and ``SharedSecret`` prevents implicit
struct value copying of raw pointers and eliminates double-free vulnerabilities.

.. code-block:: text

   +---------------------------------------------------------------+
   | Crystal Reference Handle Layer                                |
   |  - PrivateKeyPointer, Ed25519KeyPair, X25519KeyPair (class)   |
   |  - SharedSecret (class)                                       |
   |  - PublicKey, Signature (immutable value structs)             |
   |  - Sync::Mutex guards entire FFI usage and disposal spans     |
   +---------------------------------------------------------------+
                                 |
                                 v
   +---------------------------------------------------------------+
   | libsodium Secure Memory Arena (mlock + mprotect + guard)      |
   |  - Private keys (Ed25519 64 bytes, X25519 32 bytes)           |
   |  - Shared secrets (X25519 32 bytes)                           |
   |  - Marked READONLY via sodium_mprotect_readonly after write   |
   +---------------------------------------------------------------+

GC Boundary and Concurrency Rules
---------------------------------

#. **No Secret Material in GC Heap**: Private keys and unconsumed shared secrets reside exclusively in ``sodium_malloc`` regions. Public keys and signatures reside in value structs that return defensive copies via ``#bytes`` and ``#to_bytes``.
#. **Mutex-Synchronized Pointer Lifetimes**: ``PrivateKeyPointer#with_pointer`` and ``SharedSecret#consume`` hold ``@mutex.synchronize`` across the entire FFI call or consumption block so concurrent ``dispose`` calls on other fibers cannot cause a TOCTOU Use-After-Free.
#. **Hardware Page Protection Lifecycle**:

   * ``sodium_malloc``: Allocate in secure arena (initially read-write).
   * Write key or shared secret via FFI.
   * ``sodium_mprotect_readonly``: Lock memory pages to read-only while at rest and during read-only cryptographic operations.
   * ``sodium_mprotect_readwrite``: Re-enable write access under lock immediately prior to zeroization.
   * ``sodium_memzero``: Deterministically wipe secret bytes before freeing.
   * ``sodium_free``: Return pages to the libsodium arena.

Type System Design
==================

Secure Memory Wrappers
----------------------

.. code-block:: crystal

   class PrivateKeyPointer
     getter size : Int32

     def initialize(@pointer : Pointer(UInt8), @size : Int32) : Nil
       @mutex = Sync::Mutex.new
       @disposed = false
     end

     def self.allocate(size : Int32, & : Pointer(UInt8) -> Nil) : self
       Sodium.ensure_initialized
       void_ptr = LibSodium.sodium_malloc(size.to_u64)
       raise SodiumError.new("Failed to allocate secure memory") if void_ptr.null?

       ptr = void_ptr.as(Pointer(UInt8))
       begin
         yield ptr
         if LibSodium.sodium_mprotect_readonly(void_ptr) != 0
           raise SodiumError.new("Failed to mark secure memory read-only")
         end
       rescue ex
         LibSodium.sodium_mprotect_readwrite(void_ptr)
         LibSodium.sodium_memzero(void_ptr, size.to_u64)
         LibSodium.sodium_free(void_ptr)
         raise ex
       end

       new(ptr, size)
     end

     def with_pointer(& : Pointer(UInt8) -> T) : T forall T
       @mutex.synchronize do
         raise SodiumError.new("Key has been disposed") if @disposed || @pointer.null?
         yield @pointer
       end
     end

     def dispose : Nil
       @mutex.synchronize do
         return if @disposed || @pointer.null?

         LibSodium.sodium_mprotect_readwrite(@pointer.as(Void*))
         LibSodium.sodium_memzero(@pointer.as(Void*), @size.to_u64)
         LibSodium.sodium_free(@pointer.as(Void*))
         @pointer = Pointer(UInt8).null
         @disposed = true
       end
     end
   end

Public Value Types
------------------

.. code-block:: crystal

   struct PublicKey
     @bytes : Bytes

     def initialize(bytes : Bytes) : Nil
       raise ArgumentError.new("Invalid public key size: expected 32 bytes, got #{bytes.size}") unless bytes.size == 32
       @bytes = bytes.dup
     end

     def bytes : Bytes
       @bytes.dup
     end

     def to_bytes : Bytes
       @bytes.dup
     end

     def verify_ed25519(message : Bytes, signature : Signature) : Bool
       Sodium.ensure_initialized
       res = LibSodium.crypto_sign_verify_detached(
         signature.raw_bytes.to_unsafe,
         message.to_unsafe,
         message.size.to_u64,
         @bytes.to_unsafe
       )
       res == 0
     end

     def ==(other : self) : Bool
       Sodium.constant_time_equal?(@bytes, other.raw_bytes)
     end

     protected def raw_bytes : Bytes
       @bytes
     end
   end

Key Pair and Shared Secret Types
--------------------------------

.. code-block:: crystal

   class Ed25519KeyPair
     getter public_key : PublicKey

     def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer) : Nil
       return if @private_key.size == 64

       raise ArgumentError.new("Invalid Ed25519 private key size: expected 64 bytes, got #{@private_key.size}")
     end

     def sign(message : Bytes) : Signature
       sig = Bytes.new(64)
       siglen = 0_u64

       @private_key.with_pointer do |secret_key|
         res = LibSodium.crypto_sign_detached(
           sig.to_unsafe,
           pointerof(siglen),
           message.to_unsafe,
           message.size.to_u64,
           secret_key
         )
         raise SodiumError.new("Failed to sign message") if res != 0
       end

       Signature.new(sig)
     end

     def verify(message : Bytes, signature : Signature) : Bool
       @public_key.verify_ed25519(message, signature)
     end
   end

FFI Bindings
============

.. code-block:: crystal

   @[Link("sodium")]
   lib LibSodium
     fun sodium_init : Int32
     fun sodium_version_string : UInt8*
     fun sodium_library_version_major : Int32
     fun sodium_library_version_minor : Int32

     fun crypto_sign_keypair(pk : UInt8*, sk : UInt8*) : Int32
     fun crypto_sign_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : Int32
     fun crypto_sign_detached(sig : UInt8*, siglen_p : UInt64*, m : UInt8*, mlen : UInt64, sk : UInt8*) : Int32
     fun crypto_sign_verify_detached(sig : UInt8*, m : UInt8*, mlen : UInt64, pk : UInt8*) : Int32

     fun crypto_box_keypair(pk : UInt8*, sk : UInt8*) : Int32
     fun crypto_box_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : Int32
     fun crypto_scalarmult(q : UInt8*, n : UInt8*, p : UInt8*) : Int32
     fun crypto_scalarmult_base(q : UInt8*, n : UInt8*) : Int32

     fun sodium_memcmp(b1 : UInt8*, b2 : UInt8*, len : LibC::SizeT) : Int32
     fun sodium_memzero(pnt : Void*, len : LibC::SizeT)

     fun sodium_malloc(size : LibC::SizeT) : Void*
     fun sodium_free(ptr : Void*)
     fun sodium_mprotect_noaccess(ptr : Void*) : Int32
     fun sodium_mprotect_readonly(ptr : Void*) : Int32
     fun sodium_mprotect_readwrite(ptr : Void*) : Int32
   end

Initialization and Verification
===============================

.. code-block:: crystal

   struct Sodium
     @@init_mutex = Sync::Mutex.new
     @@initialized = Atomic(Bool).new(false)

     def self.init : Nil
       return if @@initialized.get

       @@init_mutex.synchronize do
         return if @@initialized.get

         if LibSodium.sodium_init == -1
           raise SodiumError.new("Failed to initialize LibSodium")
         end

         if LibSodium.sodium_library_version_major < 10
           raise SodiumError.new("Unsupported libsodium version")
         end

         @@initialized.set(true)
       end
     end
   end

Security Considerations
=======================

#. **Memory Isolation**: Private keys and shared secrets reside in ``sodium_malloc`` secure memory, locked read-only via ``sodium_mprotect_readonly``.
#. **Mutex Synchronization**: All pointer reads, writes, and disposals are serialized per handle using ``Sync::Mutex``, preventing TOCTOU Use-After-Free races.
#. **Deterministic Cleanup**: ``dispose`` restores write access, zeroes memory via ``sodium_memzero``, and frees the allocation via ``sodium_free``, with a finalizer safety net.
#. **Defensive Value Copies**: ``PublicKey`` and ``Signature`` never expose their internal mutable slice to callers.
#. **Version Check**: Runtime verification of ``libsodium`` major library version ``>= 10``.

Testing Strategy
================

#. **Type Hierarchy and Immutability**: Verify ``Reference`` vs ``Struct`` inheritance and defensive slice copying.
#. **Correctness**: Deterministic seed derivation, sign/verify round-trips, and ECDH shared secret agreement.
#. **Adversarial Safety**: Reject invalid key/seed sizes, reject all-zero weak public keys, and reject operations on disposed handles.
#. **Concurrency**: Multi-fiber parallel key generation and signing stress tests.
#. **Constant-Time Equality**: Verify ``Sodium.constant_time_equal?`` across identical, distinct, mismatched-length, and empty slices.

References
==========

* `libsodium documentation <https://doc.libsodium.org/>`__
* `libsodium secure memory <https://doc.libsodium.org/memory_management>`__
* Ed25519: RFC 8032
* X25519: RFC 7748

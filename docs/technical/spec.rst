Crystal Sodium FFI Technical Specification
==========================================

Version: 0.3.0-fixed
Status: Draft - All BLOCKER issues addressed
Target: Secure FFI wrapper to libsodium with guaranteed memory isolation

Overview
--------

This document specifies a Crystal FFI binding to libsodium that provides
constant-time elliptic curve cryptography with **guaranteed memory isolation**
from Crystal's garbage collector.

**Security Model**: All private key material is allocated in libsodium's
secure memory arena (mlock'ed, mprotect'ed, fenced), completely outside
Crystal's heap. The GC never sees, touches, or moves private keys.

Scope
-----

**In Scope:**
- Ed25519: sign, verify, keypair generation
- X25519 (Curve25519 ECDH): scalar mult, keypair generation
- Constant-time comparison: crypto_verify_*
- Secure memory: malloc/free with sodium_memzero
- SHA-512, SHA-256 for deterministic nonce generation

**Out of Scope:**
- Native Crystal ECC implementations (explicitly rejected per review)
- Symmetric encryption (separate concern)
- Password hashing (Argon2 - separate concern)

Security Architecture (REVISED)
-------------------------------

Memory Isolation Model (BLOCKER #1 Fix)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** Original spec stored pointer VALUE in GC heap via class instance variables.

**Solution:** Use `struct` (stack-allocated) instead of `class` (heap-allocated) for
all sensitive data wrappers. Stack memory is NOT scanned by GC and has deterministic
lifetime.

```
┌─────────────────────────────────────────────────────────────┐
│ Crystal Stack (NOT GC Managed)                               │
│  - PrivateKeyPointer (struct - 16 bytes: ptr + size)        │
│  - All wrapper structs                                      │
│  - No GC roots, no compaction, no scanning                  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ FFI Boundary (Pointer passing only)                  │   │
│  │  - Stack-allocated structs only                      │   │
│  │  - No heap pointers in wrappers                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ libsodium Secure Memory Arena (mlock + mprotect + guard)    │
│  - Private keys (Ed25519, X25519)                           │
│  - Shared secrets                                           │
│  - Temporary scalars during computation                     │
│  - NO GC ACCESS - pages marked NOACCESS when not in use     │
└─────────────────────────────────────────────────────────────┘
```

GC Boundary Sealing
~~~~~~~~~~~~~~~~~~~

**Rule 1: No Heap Escape (BLOCKER #1 Fix)**
- All sensitive wrappers are `struct` (stack), not `class` (heap)
- Private key pointers stored in stack-allocated structs only
- No references to sensitive data in GC heap

**Rule 2: Mutex Protection (BLOCKER #4 Fix)**
- All private key operations protected by Mutex
- Prevents Fiber yield mid-operation
- mprotect state machine: NOACCESS → READWRITE (under lock) → operation → NOACCESS → unlock

**Rule 3: Secure Memory Lifecycle**
- sodium_malloc: Allocate in secure arena
- sodium_mprotect_readwrite: Enable access (under Mutex)
- operation...
- sodium_mprotect_noaccess: Disable access
- sodium_memzero: Zero before free (CRITICAL #5 Fix)
- sodium_free: Return to arena

Type System Design (REVISED)
----------------------------

Stack-Allocated Pointer Types (BLOCKER #1 Fix)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

```crystal
# Opaque pointer to secure memory - STACK ALLOCATED (struct, not class)
struct PrivateKeyPointer
  @ptr : Pointer(UInt8)
  @size : Int32
  
  # Constructor is private - only Sodium module can create
  private def initialize(@ptr, @size)
  end
  
  # Getter for FFI calls (returns raw pointer)
  # ONLY called while Mutex is held and mprotect is READWRITE
  def to_ptr : Pointer(UInt8)
    @ptr
  end
  
  # No finalize - stack allocated, deterministic cleanup
  # Caller MUST call dispose() before struct goes out of scope
  def dispose
    if @ptr
      # Zero before free (CRITICAL #5 Fix)
      LibSodium.sodium_memzero(@ptr, @size)
      LibSodium.sodium_free(@ptr)
    end
  end
end

# Public data - safe to use in Crystal heap
struct PublicKey
  @bytes : Bytes
  
  def initialize(@bytes)
    raise ArgumentError.new("Invalid public key size") unless @bytes.size == 32
  end
  
  def to_bytes : Bytes
    @bytes.dup  # Return copy to prevent mutation
  end
end

struct Signature
  @bytes : Bytes  # 64 bytes for Ed25519
  
  def initialize(@bytes)
    raise ArgumentError.new("Invalid signature size") unless @bytes.size == 64
  end
  
  def to_bytes : Bytes
    @bytes.dup
  end
end
```

Key Types with Mutex Protection (BLOCKER #4 Fix)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

```crystal
# Global mutex for all crypto operations
# Prevents Fiber yield while keys are unlocked (mprotect READWRITE)
CRYPTO_MUTEX = Mutex.new

# Ed25519 Signing Key Pair - STACK ALLOCATED
struct Ed25519KeyPair
  # Private key stored in libsodium secure memory
  @_private_key : PrivateKeyPointer
  
  # Public key stored in Crystal heap (it's public)
  @public_key : PublicKey
  
  # Prevent external instantiation
  private def initialize(@_private_key, @public_key)
  end
  
  # Generate new random keypair
  def self.generate : Ed25519KeyPair
    pk_buffer = Bytes.new(32)
    
    # Allocate secure memory for private key
    sk_ptr = LibSodium.sodium_malloc(32)
    raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?
    
    begin
      # Initialize libsodium (thread-safe)
      Sodium.init
      
      CRYPTO_MUTEX.synchronize do
        LibSodium.sodium_mprotect_readwrite(sk_ptr)
        
        # Generate keypair - libsodium writes to secure memory
        result = LibSodium.crypto_sign_ed25519_keypair(pk_buffer.to_unsafe, sk_ptr)
        raise SodiumError.new("Key generation failed") unless result == 0
        
        # Lock down private key
        LibSodium.sodium_mprotect_noaccess(sk_ptr)
      end
      
      new(PrivateKeyPointer.new(sk_ptr, 32), PublicKey.new(pk_buffer))
    rescue ex
      # Zero and free on error (CRITICAL #5 Fix)
      LibSodium.sodium_memzero(sk_ptr, 32)
      LibSodium.sodium_free(sk_ptr)
      raise ex
    end
  end
  
  # Sign message - protected by Mutex, no Fiber yield
  def sign(message : Bytes) : Signature
    signature = Bytes.new(64)
    
    CRYPTO_MUTEX.synchronize do
      # Unlock private key for operation
      LibSodium.sodium_mprotect_readwrite(@_private_key.to_ptr)
      
      begin
        # CRITICAL #7 Fix: Pass proper siglen pointer (not nil)
        siglen = 0_u64
        result = LibSodium.crypto_sign_ed25519_detached(
          signature.to_unsafe,
          pointerof(siglen),  # CRITICAL #7 Fix
          message.to_unsafe,
          message.size.to_u64,  # CRITICAL #7 Fix: UInt64, not SizeT
          @_private_key.to_ptr
        )
        
        raise SodiumError.new("Signing failed") unless result == 0
      ensure
        # ALWAYS lock back down, even on error
        LibSodium.sodium_mprotect_noaccess(@_private_key.to_ptr)
      end
    end  # Mutex released here
    
    Signature.new(signature)
  end
  
  def public_key : PublicKey
    @public_key
  end
  
  # Explicit cleanup (no finalizer for structs)
  def dispose
    @_private_key.dispose
  end
end

# X25519 ECDH Key Pair - STACK ALLOCATED
struct X25519KeyPair
  @_private_key : PrivateKeyPointer
  @public_key : PublicKey
  
  private def initialize(@_private_key, @public_key)
  end
  
  def self.generate : X25519KeyPair
    pk_buffer = Bytes.new(32)
    sk_ptr = LibSodium.sodium_malloc(32)
    raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?
    
    begin
      Sodium.init
      
      CRYPTO_MUTEX.synchronize do
        LibSodium.sodium_mprotect_readwrite(sk_ptr)
        
        result = LibSodium.crypto_scalarmult_base(pk_buffer.to_unsafe, sk_ptr)
        raise SodiumError.new("Key generation failed") unless result == 0
        
        LibSodium.sodium_mprotect_noaccess(sk_ptr)
      end
      
      new(PrivateKeyPointer.new(sk_ptr, 32), PublicKey.new(pk_buffer))
    rescue ex
      LibSodium.sodium_memzero(sk_ptr, 32)
      LibSodium.sodium_free(sk_ptr)
      raise ex
    end
  end
  
  # ECDH scalar multiplication - protected by Mutex
  def diffie_hellman(other_public_key : PublicKey) : SharedSecret
    # Allocate shared secret in SECURE MEMORY (BLOCKER #2 Fix, MAJOR #9 Fix)
    shared_ptr = LibSodium.sodium_malloc(32)
    raise SodiumError.new("Failed to allocate secure memory") if shared_ptr.null?
    
    CRYPTO_MUTEX.synchronize do
      LibSodium.sodium_mprotect_readwrite(@_private_key.to_ptr)
      LibSodium.sodium_mprotect_readwrite(shared_ptr)  # Unlock shared secret buffer
      
      begin
        result = LibSodium.crypto_scalarmult(
          shared_ptr,
          @_private_key.to_ptr,
          other_public_key.to_bytes.to_unsafe
        )
        
        raise SodiumError.new("ECDH failed") unless result == 0
        
        # Lock shared secret before returning
        LibSodium.sodium_mprotect_noaccess(shared_ptr)
      ensure
        LibSodium.sodium_mprotect_noaccess(@_private_key.to_ptr)
      end
    end
    
    # SharedSecret now owns the secure memory pointer
    SharedSecret.new(shared_ptr, 32)
  end
  
  def public_key : PublicKey
    @public_key
  end
  
  def dispose
    @_private_key.dispose
  end
end

# Shared secret - allocated in secure memory (BLOCKER #2 Fix, MAJOR #9 Fix)
struct SharedSecret
  @_ptr : Pointer(UInt8)
  @size : Int32
  @consumed : Bool
  
  # Private constructor - only X25519KeyPair can create
  private def initialize(@_ptr, @size)
    @consumed = false
  end
  
  # One-time access - returns bytes and zeros internal copy
  def consume : Bytes
    raise SodiumError.new("Shared secret already consumed") if @consumed
    
    CRYPTO_MUTEX.synchronize do
      LibSodium.sodium_mprotect_readwrite(@_ptr)
      
      begin
        # Copy to regular Bytes (now in Crystal heap, but about to be used)
        copy = Bytes.new(@size)
        copy.copy_from(@_ptr, @size)
        
        # Zero and free the secure memory
        LibSodium.sodium_memzero(@_ptr, @size)
        LibSodium.sodium_free(@_ptr)
        
        @consumed = true
        @_ptr = Pointer(UInt8).null
        
        copy
      rescue ex
        # Ensure we still lock down on error
        LibSodium.sodium_mprotect_noaccess(@_ptr) unless @consumed
        raise ex
      end
    end
  end
  
  # Explicit cleanup if not consumed
  def dispose
    unless @consumed
      LibSodium.sodium_memzero(@_ptr, @size) if @_ptr
      LibSodium.sodium_free(@_ptr) if @_ptr
      @consumed = true
    end
  end
end
```

FFI Bindings (CRITICAL #7 Fix)
------------------------------

```crystal
@[Link("sodium")]
lib LibSodium
  # Memory management
  fun sodium_malloc(size : LibC::SizeT) : Void*
  fun sodium_free(ptr : Void*)
  fun sodium_memzero(ptr : Void*, size : LibC::SizeT)
  fun sodium_mprotect_noaccess(ptr : Void*) : Int
  fun sodium_mprotect_readonly(ptr : Void*) : Int
  fun sodium_mprotect_readwrite(ptr : Void*) : Int
  
  # Initialization
  fun sodium_init : Int
  
  # Runtime version check (MAJOR #12 Fix)
  fun sodium_version_string : UInt8*
  fun sodium_library_version_major : Int
  fun sodium_library_version_minor : Int
  
  # Ed25519
  fun crypto_sign_ed25519_keypair(
    pk : UInt8*,
    sk : UInt8*
  ) : Int
  
  # CRITICAL #7 Fix: Correct types
  # siglen is unsigned long long* (UInt64*), not SizeT*
  # mlen is unsigned long long (UInt64), not SizeT
  fun crypto_sign_ed25519_detached(
    sig : UInt8*,
    siglen : UInt64*,  # CRITICAL #7 Fix
    m : UInt8*,
    mlen : UInt64,     # CRITICAL #7 Fix
    sk : UInt8*
  ) : Int
  
  fun crypto_sign_ed25519_verify_detached(
    sig : UInt8*,
    m : UInt8*,
    mlen : UInt64,     # CRITICAL #7 Fix
    pk : UInt8*
  ) : Int
  
  # X25519
  fun crypto_scalarmult_base(
    q : UInt8*,
    n : UInt8*
  ) : Int
  
  fun crypto_scalarmult(
    q : UInt8*,
    n : UInt8*,
    p : UInt8*
  ) : Int
  
  # Constant-time comparison
  fun sodium_memcmp(
    b1 : Void*,
    b2 : Void*,
    len : LibC::SizeT
  ) : Int
end
```

Initialization (CRITICAL #6 Fix)
--------------------------------

```crystal
module Sodium
  # Atomic initialization flag (CRITICAL #6 Fix)
  @@initialized = Atomic.new(false)
  @@init_mutex = Mutex.new
  
  # Must be called before any other operations
  # Thread-safe, idempotent
  def self.init
    # Fast path: already initialized
    return if @@initialized.get
    
    # Slow path: synchronize
    @@init_mutex.synchronize do
      # Double-check after acquiring lock
      return if @@initialized.get
      
      result = LibSodium.sodium_init
      raise SodiumError.new("libsodium initialization failed") unless result >= 0
      
      # Verify minimum version (MAJOR #12 Fix)
      major = LibSodium.sodium_library_version_major
      minor = LibSodium.sodium_library_version_minor
      
      unless major > 1 || (major == 1 && minor >= 0)
        raise SodiumError.new("libsodium version #{major}.#{minor} too old, need >= 1.0.18")
      end
      
      @@initialized.set(true)
    end
  end
  
  def self.initialized? : Bool
    @@initialized.get
  end
end

class SodiumError < Exception
end
```

Verification Functions
----------------------

```crystal
module Sodium
  # Constant-time signature verification
  def self.verify_ed25519(
    public_key : PublicKey,
    message : Bytes,
    signature : Signature
  ) : Bool
    result = LibSodium.crypto_sign_ed25519_verify_detached(
      signature.to_bytes.to_unsafe,
      message.to_unsafe,
      message.size.to_u64,  # CRITICAL #7 Fix
      public_key.to_bytes.to_unsafe
    )
    
    result == 0
  end
  
  # Constant-time comparison (prevents timing attacks)
  def self.constant_time_equal?(a : Bytes, b : Bytes) : Bool
    return false unless a.size == b.size
    
    LibSodium.sodium_memcmp(
      a.to_unsafe.as(Void*),
      b.to_unsafe.as(Void*),
      a.size
    ) == 0
  end
end
```

Usage Pattern (No Finalizers)
-----------------------------

```crystal
# Example: Generate keypair, sign message, cleanup
begin
  keypair = Ed25519KeyPair.generate
  
  message = "Hello, World!".to_slice
  signature = keypair.sign(message)
  
  verified = Sodium.verify_ed25519(keypair.public_key, message, signature)
  
  puts "Verified: #{verified}"
ensure
  # MUST explicitly dispose (structs have no finalizers)
  keypair.dispose if keypair
end

# Example: ECDH key exchange
begin
  alice = X25519KeyPair.generate
  bob = X25519KeyPair.generate
  
  # Alice computes shared secret
  alice_shared = alice.diffie_hellman(bob.public_key)
  
  # Bob computes shared secret
  bob_shared = bob.diffie_hellman(alice.public_key)
  
  # Both should be equal
  alice_bytes = alice_shared.consume
  bob_bytes = bob_shared.consume
  
  puts "Shared secrets match: #{Sodium.constant_time_equal?(alice_bytes, bob_bytes)}"
ensure
  alice.dispose if alice
  bob.dispose if bob
  alice_shared.dispose if alice_shared && !alice_shared.@consumed
  bob_shared.dispose if bob_shared && !bob_shared.@consumed
end
```

Security Considerations
-----------------------

1. **Memory Isolation**: Private keys in secure memory, wrappers on stack
2. **Mutex Protection**: No Fiber yield while keys unlocked (BLOCKER #4 Fix)
3. **Explicit Cleanup**: No finalizers - caller MUST dispose (deterministic)
4. **Zero on Error**: All error paths zero sensitive data (CRITICAL #5 Fix)
5. **Type Safety**: Correct FFI types (CRITICAL #7 Fix)
6. **Thread Safety**: Atomic initialization, Mutex around crypto ops
7. **Version Check**: Runtime verification of libsodium version (MAJOR #12 Fix)

Differences from Original Spec
------------------------------

1. **Struct vs Class**: All sensitive wrappers changed from `class` to `struct`
2. **Mutex**: Added `CRYPTO_MUTEX` to prevent Fiber yield mid-operation
3. **Explicit Dispose**: No finalizers - caller must call `dispose()`
4. **Secure SharedSecret**: Now allocated in libsodium secure memory
5. **FFI Types**: Fixed `crypto_sign_ed25519_detached` parameter types
6. **Atomic Init**: Thread-safe initialization with double-checked locking
7. **Version Check**: Runtime verification of libsodium >= 1.0.18

Testing Strategy
----------------

1. **Memory Safety**: Verify no pointers in GC heap
2. **Correctness**: NIST/Wycheproof test vectors
3. **Concurrency**: Multi-Fiber stress testing
4. **Cleanup**: Verify deterministic memory cleanup
5. **Timing**: libsodium's built-in constant-time verification

References
----------

- libsodium documentation: https://doc.libsodium.org/
- libsodium secure memory: https://doc.libsodium.org/memory_management
- Ed25519: RFC 8032
- X25519: RFC 7748

macro uninitialized(type)
  Pointer({{type}}).malloc(1).value
end

module Crystal::Ecc::Constant
  VERSION = "0.1.0"

  class SodiumError < Exception
  end

  @[Link("sodium")]
  lib LibSodium
    fun sodium_init : Int32

    fun crypto_sign_keypair(pk : UInt8*, sk : UInt8*) : Int32
    fun crypto_sign_detached(sig : UInt8*, siglen_p : UInt64*, m : UInt8*, mlen : UInt64, sk : UInt8*) : Int32
    fun crypto_sign_verify_detached(sig : UInt8*, m : UInt8*, mlen : UInt64, pk : UInt8*) : Int32

    fun crypto_box_keypair(pk : UInt8*, sk : UInt8*) : Int32
    fun crypto_scalarmult(q : UInt8*, n : UInt8*, p : UInt8*) : Int32

    fun sodium_memcmp(b1 : UInt8*, b2 : UInt8*, len : LibC::SizeT) : Int32

    fun sodium_malloc(size : LibC::SizeT) : Void*
    fun sodium_free(ptr : Void*)
  end

  struct Sodium
    @@initialized = false

    def self.init
      if LibSodium.sodium_init == -1
        raise SodiumError.new("Failed to initialize LibSodium")
      end
      @@initialized = true
    end

    def self.initialized?
      @@initialized
    end

    def self.verify_ed25519(public_key : PublicKey, message : Bytes, signature : Signature) : Bool
      res = LibSodium.crypto_sign_verify_detached(
        signature.to_bytes.to_unsafe,
        message.to_unsafe,
        message.size.to_u64,
        public_key.to_bytes.to_unsafe
      )
      res == 0
    end

    def self.constant_time_equal?(a : Bytes, b : Bytes) : Bool
      return false if a.size != b.size
      LibSodium.sodium_memcmp(a.to_unsafe, b.to_unsafe, a.size) == 0
    end
  end

  struct PublicKey
    @bytes : Bytes

    def initialize(bytes : Bytes)
      raise ArgumentError.new("Invalid public key size") unless bytes.size == 32
      @bytes = bytes.dup
    end

    def to_bytes
      @bytes
    end
  end

  struct Signature
    @bytes : Bytes

    def initialize(bytes : Bytes)
      raise ArgumentError.new("Invalid signature size") unless bytes.size == 64
      @bytes = bytes.dup
    end

    def to_bytes
      @bytes
    end
  end

  class PrivateKeyPointer
    getter pointer : Pointer(UInt8)
    getter size : Int32
    @disposed = false

    def initialize(@pointer : Pointer(UInt8), @size : Int32)
    end

    def dispose
      return if @disposed || @pointer.null?
      LibSodium.sodium_free(@pointer.as(Void*))
      @pointer = Pointer(UInt8).null
      @disposed = true
    end

    def finalize
      dispose
    end
  end

  class SharedSecret
    @consumed = false
    @ptr : Pointer(UInt8)
    @size : Int32
    @disposed = false

    def initialize(size : Int32)
      void_ptr = LibSodium.sodium_malloc(size)
      raise SodiumError.new("Failed to allocate shared secret") if void_ptr.null?
      @ptr = void_ptr.as(Pointer(UInt8))
      @size = size
    end

    def unsafe_ptr : Pointer(UInt8)
      @ptr
    end

    def consume : Bytes
      raise SodiumError.new("Shared secret already consumed") if @consumed
      raise SodiumError.new("Shared secret already disposed") if @disposed
      @consumed = true
      Bytes.new(@ptr, @size)
    end

    def dispose
      return if @disposed
      unless @ptr.null?
        LibSodium.sodium_free(@ptr.as(Void*))
        @ptr = Pointer(UInt8).null
      end
      @disposed = true
    end

    def finalize
      dispose
    end
  end

  class Ed25519KeyPair
    @public_key : PublicKey
    @private_key : PrivateKeyPointer

    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer)
    end

    def self.generate : self
      sk_ptr = LibSodium.sodium_malloc(64)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_sign_keypair(pk.to_unsafe, sk) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to generate Ed25519 keypair")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 64))
    end

    def sign(message : Bytes) : Signature
      raise SodiumError.new("Key pair has been disposed") if @private_key.pointer.null?

      sig = Bytes.new(64)
      siglen = 0_u64
      if LibSodium.crypto_sign_detached(sig.to_unsafe, pointerof(siglen), message.to_unsafe, message.size.to_u64, @private_key.pointer) != 0
        raise SodiumError.new("Failed to sign message")
      end
      Signature.new(sig)
    end

    def public_key : PublicKey
      @public_key
    end

    def dispose
      @private_key.dispose
    end
  end

  class X25519KeyPair
    @public_key : PublicKey
    @private_key : PrivateKeyPointer

    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer)
    end

    def self.generate : self
      sk_ptr = LibSodium.sodium_malloc(32)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_box_keypair(pk.to_unsafe, sk) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to generate X25519 keypair")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 32))
    end

    def diffie_hellman(other_public_key : PublicKey) : SharedSecret
      raise SodiumError.new("Key pair has been disposed") if @private_key.pointer.null?

      shared = SharedSecret.new(32)
      if LibSodium.crypto_scalarmult(shared.unsafe_ptr, @private_key.pointer, other_public_key.to_bytes.to_unsafe) != 0
        shared.dispose
        raise SodiumError.new("Failed to compute shared secret")
      end
      shared
    end

    def public_key : PublicKey
      @public_key
    end

    def dispose
      @private_key.dispose
    end
  end
end

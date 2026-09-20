module Crystal::Ecc::Constant
  class X25519KeyPair
    getter public_key : PublicKey

    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer)
    end

    def self.generate : self
      Sodium.ensure_initialized
      sk_ptr = LibSodium.sodium_malloc(32_u64)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_box_keypair(pk.to_unsafe, sk) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to generate X25519 keypair")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 32))
    end

    def self.from_seed(seed : Bytes) : self
      Sodium.ensure_initialized
      raise ArgumentError.new("X25519 seed must be exactly 32 bytes, got #{seed.size}") unless seed.size == 32

      sk_ptr = LibSodium.sodium_malloc(32_u64)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_box_seed_keypair(pk.to_unsafe, sk, seed.to_unsafe) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to derive X25519 keypair from seed")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 32))
    end

    def diffie_hellman(other_public_key : PublicKey) : SharedSecret
      raise SodiumError.new("Key pair has been disposed") if @private_key.disposed?

      shared = SharedSecret.new(32)
      res = LibSodium.crypto_scalarmult(
        shared.unsafe_ptr,
        @private_key.pointer,
        other_public_key.bytes.to_unsafe
      )

      if res != 0
        shared.dispose
        raise SodiumError.new("Failed to compute shared secret: weak or invalid key")
      end

      shared
    end

    def disposed? : Bool
      @private_key.disposed?
    end

    def dispose : Nil
      @private_key.dispose
    end
  end
end

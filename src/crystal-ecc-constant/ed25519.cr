module Crystal::Ecc::Constant
  class Ed25519KeyPair
    getter public_key : PublicKey

    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer)
    end

    def self.generate : self
      Sodium.ensure_initialized
      sk_ptr = LibSodium.sodium_malloc(64_u64)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_sign_keypair(pk.to_unsafe, sk) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to generate Ed25519 keypair")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 64))
    end

    def self.from_seed(seed : Bytes) : self
      Sodium.ensure_initialized
      raise ArgumentError.new("Ed25519 seed must be exactly 32 bytes, got #{seed.size}") unless seed.size == 32

      sk_ptr = LibSodium.sodium_malloc(64_u64)
      raise SodiumError.new("Failed to allocate secure memory") if sk_ptr.null?

      sk = sk_ptr.as(Pointer(UInt8))
      pk = Bytes.new(32)

      if LibSodium.crypto_sign_seed_keypair(pk.to_unsafe, sk, seed.to_unsafe) != 0
        LibSodium.sodium_free(sk_ptr)
        raise SodiumError.new("Failed to derive Ed25519 keypair from seed")
      end

      new(PublicKey.new(pk), PrivateKeyPointer.new(sk, 64))
    end

    def sign(message : Bytes) : Signature
      raise SodiumError.new("Key pair has been disposed") if @private_key.disposed?

      sig = Bytes.new(64)
      siglen = 0_u64
      res = LibSodium.crypto_sign_detached(
        sig.to_unsafe,
        pointerof(siglen),
        message.to_unsafe,
        message.size.to_u64,
        @private_key.pointer
      )

      if res != 0
        raise SodiumError.new("Failed to sign message")
      end

      Signature.new(sig)
    end

    def disposed? : Bool
      @private_key.disposed?
    end

    def dispose : Nil
      @private_key.dispose
    end
  end
end

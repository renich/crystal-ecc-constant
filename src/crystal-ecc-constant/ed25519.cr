module Crystal::Ecc::Constant
  # Ed25519 key pair holding a public key and a pinned secure memory private key.
  class Ed25519KeyPair
    # The 32-byte Ed25519 public key.
    getter public_key : PublicKey

    # Initializes an Ed25519 key pair from a `PublicKey` and a 64-byte `PrivateKeyPointer`.
    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer) : Nil
      return if @private_key.size == 64

      raise ArgumentError.new("Invalid Ed25519 private key size: expected 64 bytes, got #{@private_key.size}")
    end

    # Generates a new random Ed25519 key pair in libsodium secure memory.
    def self.generate : self
      pk = Bytes.new(32)
      sk_ptr = PrivateKeyPointer.allocate(64) do |secret_key|
        if LibSodium.crypto_sign_keypair(pk.to_unsafe, secret_key) != 0
          raise SodiumError.new("Failed to generate Ed25519 keypair")
        end
      end

      new(PublicKey.new(pk), sk_ptr)
    end

    # Derives a deterministic Ed25519 key pair from a 32-byte cryptographic `seed`.
    def self.from_seed(seed : Bytes) : self
      raise ArgumentError.new("Ed25519 seed must be exactly 32 bytes, got #{seed.size}") unless seed.size == 32

      pk = Bytes.new(32)
      sk_ptr = PrivateKeyPointer.allocate(64) do |secret_key|
        if LibSodium.crypto_sign_seed_keypair(pk.to_unsafe, secret_key, seed.to_unsafe) != 0
          raise SodiumError.new("Failed to derive Ed25519 keypair from seed")
        end
      end

      new(PublicKey.new(pk), sk_ptr)
    end

    # Verifies an Ed25519 detached `signature` against `message` and `public_key` in constant time.
    def self.verify_detached(public_key : PublicKey, message : Bytes, signature : Signature) : Bool
      public_key.verify_ed25519(message, signature)
    end

    # Produces a 64-byte detached Ed25519 signature for `message`.
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

        if res != 0
          raise SodiumError.new("Failed to sign message")
        end
      end

      Signature.new(sig)
    end

    # Verifies an Ed25519 detached `signature` for `message` using this key pair's public key.
    def verify(message : Bytes, signature : Signature) : Bool
      @public_key.verify_ed25519(message, signature)
    end

    # Returns `true` if the underlying private key has been wiped and freed.
    def disposed? : Bool
      @private_key.disposed?
    end

    # Wipes and frees the underlying private key in secure memory.
    def dispose : Nil
      @private_key.dispose
    end

    protected def with_secret_key(& : Pointer(UInt8) -> T) : T forall T
      @private_key.with_pointer do |secret_key|
        yield secret_key
      end
    end
  end
end

module Crystal::Ecc::Constant
  # X25519 key pair for Elliptic Curve Diffie-Hellman (ECDH) key exchange.
  class X25519KeyPair
    # The 32-byte X25519 public key.
    getter public_key : PublicKey

    # Initializes an X25519 key pair from a `PublicKey` and a 32-byte `PrivateKeyPointer`.
    def initialize(@public_key : PublicKey, @private_key : PrivateKeyPointer) : Nil
      return if @private_key.size == 32

      raise ArgumentError.new("Invalid X25519 private key size: expected 32 bytes, got #{@private_key.size}")
    end

    # Generates a new random X25519 key pair in libsodium secure memory.
    def self.generate : self
      pk = Bytes.new(32)
      sk_ptr = PrivateKeyPointer.allocate(32) do |secret_key|
        if LibSodium.crypto_box_keypair(pk.to_unsafe, secret_key) != 0
          raise SodiumError.new("Failed to generate X25519 keypair")
        end
      end

      new(PublicKey.new(pk), sk_ptr)
    end

    # Derives a deterministic X25519 key pair from a 32-byte cryptographic `seed`.
    def self.from_seed(seed : Bytes) : self
      raise ArgumentError.new("X25519 seed must be exactly 32 bytes, got #{seed.size}") unless seed.size == 32

      pk = Bytes.new(32)
      sk_ptr = PrivateKeyPointer.allocate(32) do |secret_key|
        if LibSodium.crypto_box_seed_keypair(pk.to_unsafe, secret_key, seed.to_unsafe) != 0
          raise SodiumError.new("Failed to derive X25519 keypair from seed")
        end
      end

      new(PublicKey.new(pk), sk_ptr)
    end

    # Computes a 32-byte ECDH `SharedSecret` with `other_public_key` in libsodium secure memory.
    def diffie_hellman(other_public_key : PublicKey) : SharedSecret
      @private_key.with_pointer do |secret_key|
        shared = SharedSecret.new(32)
        res = shared.with_unsafe_ptr do |sh_ptr|
          LibSodium.crypto_scalarmult(
            sh_ptr,
            secret_key,
            other_public_key.raw_bytes.to_unsafe
          )
        end

        if res != 0
          shared.dispose
          raise SodiumError.new("Failed to compute shared secret: weak or invalid key")
        end

        shared
      end
    end

    # Returns `true` if the underlying private key has been wiped and freed.
    def disposed? : Bool
      @private_key.disposed?
    end

    # Wipes and frees the underlying private key in secure memory.
    def dispose : Nil
      @private_key.dispose
    end
  end
end

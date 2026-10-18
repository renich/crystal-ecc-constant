module Crystal::Ecc::Constant
  # Raised when a libsodium operation fails or a disposed cryptographic resource is accessed.
  class SodiumError < Exception
  end

  # Immutable 32-byte public key wrapper for Ed25519 and X25519 operations.
  struct PublicKey
    @bytes : Bytes

    # Initializes a new 32-byte public key from a defensive copy of `bytes`.
    def initialize(bytes : Bytes) : Nil
      raise ArgumentError.new("Invalid public key size: expected 32 bytes, got #{bytes.size}") unless bytes.size == 32
      @bytes = bytes.dup
    end

    # Returns a defensive copy of the 32-byte public key slice.
    def bytes : Bytes
      @bytes.dup
    end

    # Returns a defensive copy of the 32-byte public key slice.
    def to_bytes : Bytes
      @bytes.dup
    end

    # Verifies an Ed25519 detached signature against `message` using this public key.
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

    # Compares two public keys in constant time.
    def ==(other : self) : Bool
      Sodium.constant_time_equal?(@bytes, other.raw_bytes)
    end

    protected def raw_bytes : Bytes
      @bytes
    end
  end

  # Immutable 64-byte Ed25519 detached signature wrapper.
  struct Signature
    @bytes : Bytes

    # Initializes a new 64-byte signature from a defensive copy of `bytes`.
    def initialize(bytes : Bytes) : Nil
      raise ArgumentError.new("Invalid signature size: expected 64 bytes, got #{bytes.size}") unless bytes.size == 64
      @bytes = bytes.dup
    end

    # Returns a defensive copy of the 64-byte signature slice.
    def bytes : Bytes
      @bytes.dup
    end

    # Returns a defensive copy of the 64-byte signature slice.
    def to_bytes : Bytes
      @bytes.dup
    end

    # Compares two signatures in constant time.
    def ==(other : self) : Bool
      Sodium.constant_time_equal?(@bytes, other.raw_bytes)
    end

    protected def raw_bytes : Bytes
      @bytes
    end
  end
end

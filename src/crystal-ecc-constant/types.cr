module Crystal::Ecc::Constant
  class SodiumError < Exception
  end

  struct PublicKey
    getter bytes : Bytes

    def initialize(bytes : Bytes)
      raise ArgumentError.new("Invalid public key size: expected 32 bytes, got #{bytes.size}") unless bytes.size == 32
      @bytes = bytes.dup
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def ==(other : PublicKey) : Bool
      Sodium.constant_time_equal?(@bytes, other.bytes)
    end
  end

  struct Signature
    getter bytes : Bytes

    def initialize(bytes : Bytes)
      raise ArgumentError.new("Invalid signature size: expected 64 bytes, got #{bytes.size}") unless bytes.size == 64
      @bytes = bytes.dup
    end

    def to_bytes : Bytes
      @bytes.dup
    end

    def ==(other : Signature) : Bool
      Sodium.constant_time_equal?(@bytes, other.bytes)
    end
  end
end

module Crystal::Ecc::Constant
  # BLAKE2b hierarchical subkey derivation outputting directly into guarded `SecureBuffer` memory.
  module Kdf
    # Required master key size in bytes (`crypto_kdf_KEYBYTES`).
    KEY_BYTES = 32

    # Required context string byte length (`crypto_kdf_CONTEXTBYTES`).
    CONTEXT_BYTES = 8

    # Minimum derived subkey length in bytes (`crypto_kdf_BYTES_MIN`).
    MIN_SUBKEY_BYTES = 16

    # Maximum derived subkey length in bytes (`crypto_kdf_BYTES_MAX`).
    MAX_SUBKEY_BYTES = 64

    # Derives an isolated `subkey_size`-byte subkey in guarded memory from `master_key`, `subkey_id`, and `context`.
    def self.derive_subkey(
      master_key : SecureBuffer,
      subkey_id : UInt64,
      context : String,
      subkey_size : Int32 = 32,
    ) : SecureBuffer
      validate_params!(master_key, context, subkey_size)

      master_key.with_pointer do |master_ptr|
        SecureBuffer.allocate(subkey_size) do |subkey_ptr|
          res = LibSodium.crypto_kdf_derive_from_key(
            subkey_ptr,
            subkey_size.to_u64,
            subkey_id,
            context.to_unsafe,
            master_ptr
          )
          raise SodiumError.new("Failed to derive subkey") if res != 0
        end
      end
    end

    private def self.validate_params!(master_key : SecureBuffer, context : String, subkey_size : Int32) : Nil
      unless master_key.size == KEY_BYTES
        raise ArgumentError.new("KDF master_key must be exactly 32 bytes, got #{master_key.size}")
      end
      unless context.bytesize == CONTEXT_BYTES
        raise ArgumentError.new("KDF context must be exactly 8 bytes, got #{context.bytesize}")
      end
      return if MIN_SUBKEY_BYTES <= subkey_size <= MAX_SUBKEY_BYTES

      raise ArgumentError.new("KDF subkey_size must be between 16 and 64 bytes, got #{subkey_size}")
    end
  end
end

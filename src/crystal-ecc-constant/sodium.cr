require "sync/mutex"

module Crystal::Ecc::Constant
  struct Sodium
    @@init_mutex = Sync::Mutex.new
    @@initialized = Atomic(Bool).new(false)

    def self.init : Nil
      return if @@initialized.get

      @@init_mutex.synchronize do
        return if @@initialized.get

        result = LibSodium.sodium_init
        if result == -1
          raise SodiumError.new("Failed to initialize LibSodium")
        end
        @@initialized.set(true)
      end
    end

    def self.initialized? : Bool
      @@initialized.get
    end

    def self.ensure_initialized : Nil
      init unless initialized?
    end

    def self.version : String
      String.new(LibSodium.sodium_version_string)
    end

    def self.verify_ed25519(public_key : PublicKey, message : Bytes, signature : Signature) : Bool
      ensure_initialized
      res = LibSodium.crypto_sign_verify_detached(
        signature.bytes.to_unsafe,
        message.to_unsafe,
        message.size.to_u64,
        public_key.bytes.to_unsafe
      )
      res == 0
    end

    def self.constant_time_equal?(a : Bytes, b : Bytes) : Bool
      return true if a.empty? && b.empty?
      return false if a.size != b.size

      ensure_initialized
      LibSodium.sodium_memcmp(a.to_unsafe, b.to_unsafe, a.size) == 0
    end
  end
end

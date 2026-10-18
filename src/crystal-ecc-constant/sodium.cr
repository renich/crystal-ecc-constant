require "sync/mutex"

module Crystal::Ecc::Constant
  # Thread-safe initialization and constant-time cryptographic utilities backed by libsodium.
  struct Sodium
    @@init_mutex = Sync::Mutex.new
    @@initialized = Atomic(Bool).new(false)

    # Initializes libsodium in a thread-safe, idempotent manner and verifies the runtime version.
    def self.init : Nil
      return if @@initialized.get

      @@init_mutex.synchronize do
        return if @@initialized.get

        result = LibSodium.sodium_init
        if result == -1
          raise SodiumError.new("Failed to initialize LibSodium")
        end

        if LibSodium.sodium_library_version_major < 10
          raise SodiumError.new("Unsupported libsodium version")
        end

        @@initialized.set(true)
      end
    end

    # Returns `true` if libsodium has been initialized.
    def self.initialized? : Bool
      @@initialized.get
    end

    # Ensures libsodium is initialized before executing FFI operations.
    def self.ensure_initialized : Nil
      init unless initialized?
    end

    # Returns the runtime libsodium version string.
    def self.version : String
      String.new(LibSodium.sodium_version_string)
    end

    # Verifies an Ed25519 detached signature against a message and public key.
    def self.verify_ed25519(public_key : PublicKey, message : Bytes, signature : Signature) : Bool
      public_key.verify_ed25519(message, signature)
    end

    # Compares two byte slices in constant time using `sodium_memcmp`.
    def self.constant_time_equal?(a : Bytes, b : Bytes) : Bool
      return true if a.empty? && b.empty?
      return false if a.size != b.size

      ensure_initialized
      LibSodium.sodium_memcmp(a.to_unsafe, b.to_unsafe, a.size) == 0
    end
  end
end

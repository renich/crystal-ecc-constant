require "sync/mutex"

module Crystal::Ecc::Constant
  # Pre-hashed Ed25519ph multi-part streaming signer and verifier with guarded state memory.
  class Ed25519PhStream
    # Size in bytes of the libsodium `crypto_sign_ed25519ph_state` structure.
    STATE_BYTES = 208

    # Allocates and initializes a 208-byte `Ed25519ph` streaming state in guarded memory.
    def initialize : Nil
      Sodium.ensure_initialized
      @mutex = Sync::Mutex.new
      @disposed = false
      @state_ptr = allocate_state
    end

    # Appends `chunk` bytes into the guarded SHA-512 pre-hash state.
    def update(chunk : Bytes) : self
      @mutex.synchronize do
        ensure_active!
        unlock_state!
        begin
          res = LibSodium.crypto_sign_ed25519ph_update(@state_ptr, chunk.to_unsafe, chunk.size.to_u64)
          raise SodiumError.new("Failed to update Ed25519ph state") if res != 0
        ensure
          lock_state! unless @disposed
        end
      end
      self
    end

    # Appends `chunk` string bytes into the guarded SHA-512 pre-hash state.
    def update(chunk : String) : self
      update(chunk.to_slice)
    end

    # Finalizes the stream, produces a 64-byte `Ed25519ph` `Signature`, and wipes the guarded state.
    def final_sign(keypair : Ed25519KeyPair) : Signature
      @mutex.synchronize do
        ensure_active!
        sig = Bytes.new(64)
        siglen = 0_u64
        begin
          unlock_state!
          keypair.with_secret_key do |secret_key|
            res = LibSodium.crypto_sign_ed25519ph_final_create(@state_ptr, sig.to_unsafe, pointerof(siglen), secret_key)
            raise SodiumError.new("Failed to finalize Ed25519ph signature") if res != 0
          end
        ensure
          dispose_unlocked
        end
        Signature.new(sig)
      end
    end

    # Finalizes the stream, verifies `signature` against `public_key` in constant time, and wipes the state.
    def final_verify(public_key : PublicKey, signature : Signature) : Bool
      @mutex.synchronize do
        ensure_active!
        begin
          unlock_state!
          res = LibSodium.crypto_sign_ed25519ph_final_verify(
            @state_ptr,
            signature.raw_bytes.to_unsafe,
            public_key.raw_bytes.to_unsafe
          )
          res == 0
        ensure
          dispose_unlocked
        end
      end
    end

    # Returns `true` if the streaming state has been finalized or disposed.
    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    # Wipes and frees the underlying guarded streaming state idempotently.
    def dispose : Nil
      @mutex.synchronize { dispose_unlocked }
    end

    # Fallback finalizer ensuring guarded streaming state is wiped if not explicitly finalized.
    def finalize : Nil
      dispose
    end

    private def allocate_state : Pointer(LibSodium::CryptoSignEd25519phState)
      void_ptr = LibSodium.sodium_malloc(STATE_BYTES.to_u64)
      raise SodiumError.new("Failed to allocate Ed25519ph state") if void_ptr.null?

      state_ptr = void_ptr.as(Pointer(LibSodium::CryptoSignEd25519phState))
      if LibSodium.crypto_sign_ed25519ph_init(state_ptr) != 0 || LibSodium.sodium_mprotect_readonly(void_ptr) != 0
        LibSodium.sodium_mprotect_readwrite(void_ptr)
        LibSodium.sodium_memzero(void_ptr, STATE_BYTES.to_u64)
        LibSodium.sodium_free(void_ptr)
        raise SodiumError.new("Failed to initialize Ed25519ph state")
      end
      state_ptr
    end

    private def ensure_active! : Nil
      raise SodiumError.new("Ed25519ph stream has been disposed") if @disposed || @state_ptr.null?
    end

    private def unlock_state! : Nil
      return if LibSodium.sodium_mprotect_readwrite(@state_ptr.as(Void*)) == 0

      raise SodiumError.new("Failed to unlock Ed25519ph state")
    end

    private def lock_state! : Nil
      return if LibSodium.sodium_mprotect_readonly(@state_ptr.as(Void*)) == 0

      raise SodiumError.new("Failed to lock Ed25519ph state read-only")
    end

    private def dispose_unlocked : Nil
      return if @disposed

      unless @state_ptr.null?
        LibSodium.sodium_mprotect_readwrite(@state_ptr.as(Void*))
        LibSodium.sodium_memzero(@state_ptr.as(Void*), STATE_BYTES.to_u64)
        LibSodium.sodium_free(@state_ptr.as(Void*))
        @state_ptr = Pointer(LibSodium::CryptoSignEd25519phState).null
      end
      @disposed = true
    end
  end
end

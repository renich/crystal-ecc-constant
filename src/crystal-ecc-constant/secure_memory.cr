require "sync/mutex"

module Crystal::Ecc::Constant
  # Reference-counted wrapper managing a private key or secret buffer in libsodium secure memory.
  class PrivateKeyPointer
    # Size of the allocated private key buffer in bytes.
    getter size : Int32

    # Wraps an existing libsodium secure memory pointer of `size` bytes.
    def initialize(@pointer : Pointer(UInt8), @size : Int32) : Nil
      @mutex = Sync::Mutex.new
      @disposed = false
    end

    # Allocates `size` bytes in libsodium secure memory, yields the pointer for initialization,
    # and marks the region read-only before returning the wrapped pointer.
    def self.allocate(size : Int32, & : Pointer(UInt8) -> Nil) : self
      Sodium.ensure_initialized
      void_ptr = LibSodium.sodium_malloc(size.to_u64)
      raise SodiumError.new("Failed to allocate secure memory") if void_ptr.null?

      ptr = void_ptr.as(Pointer(UInt8))
      begin
        yield ptr
        if LibSodium.sodium_mprotect_readonly(void_ptr) != 0
          raise SodiumError.new("Failed to mark secure memory read-only")
        end
      rescue ex
        LibSodium.sodium_mprotect_readwrite(void_ptr)
        LibSodium.sodium_memzero(void_ptr, size.to_u64)
        LibSodium.sodium_free(void_ptr)
        raise ex
      end

      new(ptr, size)
    end

    # Allocates a new guarded buffer populated from `bytes` and locked read-only.
    def self.from_bytes(bytes : Bytes) : self
      raise ArgumentError.new("SecureBuffer cannot be empty") if bytes.empty?

      allocate(bytes.size) do |ptr|
        bytes.to_unsafe.copy_to(ptr, bytes.size)
      end
    end

    # Yields the underlying pointer while holding the synchronization lock to prevent concurrent disposal.
    def with_pointer(& : Pointer(UInt8) -> T) : T forall T
      @mutex.synchronize do
        raise SodiumError.new("Key has been disposed") if @disposed || @pointer.null?
        yield @pointer
      end
    end

    # Yields a read-only `Bytes` view of the guarded buffer while holding the synchronization lock.
    def with_bytes(& : Bytes -> T) : T forall T
      with_pointer do |ptr|
        yield Bytes.new(ptr, @size, read_only: true)
      end
    end

    # Returns a defensive byte slice copy of the guarded buffer.
    def to_bytes : Bytes
      with_bytes do |slice|
        copy = Bytes.new(@size)
        slice.copy_to(copy)
        copy
      end
    end

    # Returns the raw pointer if not disposed. Prefer `#with_pointer` for thread-safe FFI operations.
    def pointer : Pointer(UInt8)
      @mutex.synchronize do
        raise SodiumError.new("Key has been disposed") if @disposed || @pointer.null?
        @pointer
      end
    end

    # Returns `true` if the underlying secure memory has been wiped and freed.
    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    # Wipes and frees the underlying libsodium secure memory region idempotently.
    def dispose : Nil
      @mutex.synchronize do
        return if @disposed || @pointer.null?

        LibSodium.sodium_mprotect_readwrite(@pointer.as(Void*))
        LibSodium.sodium_memzero(@pointer.as(Void*), @size.to_u64)
        LibSodium.sodium_free(@pointer.as(Void*))
        @pointer = Pointer(UInt8).null
        @disposed = true
      end
    end

    # Fallback finalizer that ensures secure memory is wiped if explicit disposal was omitted.
    def finalize : Nil
      dispose
    end
  end

  # Alias for `PrivateKeyPointer` representing a guarded memory secret buffer.
  alias SecureBuffer = PrivateKeyPointer

  # Single-use wrapper managing an ECDH shared secret in libsodium secure memory.
  class SharedSecret
    # Size of the allocated shared secret buffer in bytes.
    getter size : Int32

    # Allocates a new shared secret buffer of `size` bytes in libsodium secure memory.
    def initialize(@size : Int32) : Nil
      Sodium.ensure_initialized
      @mutex = Sync::Mutex.new
      @consumed = false
      @disposed = false

      void_ptr = LibSodium.sodium_malloc(@size.to_u64)
      raise SodiumError.new("Failed to allocate shared secret") if void_ptr.null?
      if LibSodium.sodium_mprotect_readonly(void_ptr) != 0
        LibSodium.sodium_memzero(void_ptr, @size.to_u64)
        LibSodium.sodium_free(void_ptr)
        raise SodiumError.new("sodium_mprotect_readonly failed")
      end
      @ptr = void_ptr.as(Pointer(UInt8))
    end

    # Yields the raw pointer under lock for initialization and then marks the memory read-only.
    def with_unsafe_ptr(& : Pointer(UInt8) -> T) : T forall T
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already disposed") if @disposed || @ptr.null?
        if LibSodium.sodium_mprotect_readwrite(@ptr.as(Void*)) != 0
          raise SodiumError.new("sodium_mprotect_readwrite failed")
        end
        begin
          yield @ptr
        ensure
          if !@disposed && !@ptr.null? && LibSodium.sodium_mprotect_readonly(@ptr.as(Void*)) != 0
            raise SodiumError.new("sodium_mprotect_readonly failed")
          end
        end
      end
    end

    # Returns the raw pointer if not disposed. Prefer `#with_unsafe_ptr` for synchronized writes.
    def unsafe_ptr : Pointer(UInt8)
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already disposed") if @disposed || @ptr.null?
        @ptr
      end
    end

    # Returns `true` if the shared secret has been consumed.
    def consumed? : Bool
      @mutex.synchronize { @consumed }
    end

    # Returns `true` if the shared secret memory has been wiped and freed.
    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    # Yields a read-only view of the shared secret bytes under lock and deterministically wipes
    # and frees the underlying secure memory before returning.
    def consume(& : Bytes -> T) : T forall T
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already consumed") if @consumed
        raise SodiumError.new("Shared secret already disposed") if @disposed || @ptr.null?
        @consumed = true

        slice = Bytes.new(@ptr, @size, read_only: true)
        begin
          yield slice
        ensure
          dispose_unlocked
        end
      end
    end

    # Copies the shared secret into a fresh byte slice, immediately wiping and freeing the secure memory.
    def consume : Bytes
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already consumed") if @consumed
        raise SodiumError.new("Shared secret already disposed") if @disposed || @ptr.null?
        @consumed = true

        copy = Bytes.new(@size)
        Bytes.new(@ptr, @size, read_only: true).copy_to(copy)
        dispose_unlocked
        copy
      end
    end

    # Wipes and frees the underlying secure memory idempotently.
    def dispose : Nil
      @mutex.synchronize do
        dispose_unlocked
      end
    end

    # Fallback finalizer that ensures secure memory is wiped if explicit disposal was omitted.
    def finalize : Nil
      dispose
    end

    private def dispose_unlocked : Nil
      return if @disposed
      unless @ptr.null?
        LibSodium.sodium_mprotect_readwrite(@ptr.as(Void*))
        LibSodium.sodium_memzero(@ptr.as(Void*), @size.to_u64)
        LibSodium.sodium_free(@ptr.as(Void*))
        @ptr = Pointer(UInt8).null
      end
      @disposed = true
    end
  end
end

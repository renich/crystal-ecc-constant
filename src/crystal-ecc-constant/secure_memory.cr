require "sync/mutex"

module Crystal::Ecc::Constant
  class PrivateKeyPointer
    getter size : Int32

    def initialize(@pointer : Pointer(UInt8), @size : Int32)
      @mutex = Sync::Mutex.new
      @disposed = false
    end

    def pointer : Pointer(UInt8)
      @mutex.synchronize do
        raise SodiumError.new("Key has been disposed") if @disposed || @pointer.null?
        @pointer
      end
    end

    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    def dispose : Nil
      @mutex.synchronize do
        return if @disposed || @pointer.null?

        LibSodium.sodium_memzero(@pointer.as(Void*), @size.to_u64)
        LibSodium.sodium_free(@pointer.as(Void*))
        @pointer = Pointer(UInt8).null
        @disposed = true
      end
    end

    def finalize
      dispose
    end
  end

  class SharedSecret
    getter size : Int32

    def initialize(@size : Int32)
      Sodium.ensure_initialized
      @mutex = Sync::Mutex.new
      @consumed = false
      @disposed = false

      void_ptr = LibSodium.sodium_malloc(@size.to_u64)
      raise SodiumError.new("Failed to allocate shared secret") if void_ptr.null?
      @ptr = void_ptr.as(Pointer(UInt8))
    end

    def unsafe_ptr : Pointer(UInt8)
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already disposed") if @disposed || @ptr.null?
        @ptr
      end
    end

    def consumed? : Bool
      @mutex.synchronize { @consumed }
    end

    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    def consume(& : Bytes -> T) : T forall T
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already consumed") if @consumed
        raise SodiumError.new("Shared secret already disposed") if @disposed
        @consumed = true
      end

      slice = Bytes.new(@ptr, @size)
      begin
        yield slice
      ensure
        dispose
      end
    end

    def consume : Bytes
      @mutex.synchronize do
        raise SodiumError.new("Shared secret already consumed") if @consumed
        raise SodiumError.new("Shared secret already disposed") if @disposed
        @consumed = true

        copy = Bytes.new(@size)
        Bytes.new(@ptr, @size).copy_to(copy)

        LibSodium.sodium_memzero(@ptr.as(Void*), @size.to_u64)
        LibSodium.sodium_free(@ptr.as(Void*))
        @ptr = Pointer(UInt8).null
        @disposed = true

        copy
      end
    end

    def dispose : Nil
      @mutex.synchronize do
        return if @disposed
        unless @ptr.null?
          LibSodium.sodium_memzero(@ptr.as(Void*), @size.to_u64)
          LibSodium.sodium_free(@ptr.as(Void*))
          @ptr = Pointer(UInt8).null
        end
        @disposed = true
      end
    end

    def finalize
      dispose
    end
  end
end

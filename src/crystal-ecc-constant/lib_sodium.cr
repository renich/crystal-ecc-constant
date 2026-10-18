module Crystal::Ecc::Constant
  # Low-level C ABI bindings to libsodium.
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init : Int32
    fun sodium_version_string : UInt8*
    fun sodium_library_version_major : Int32
    fun sodium_library_version_minor : Int32

    fun crypto_sign_keypair(pk : UInt8*, sk : UInt8*) : Int32
    fun crypto_sign_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : Int32
    fun crypto_sign_detached(sig : UInt8*, siglen_p : UInt64*, m : UInt8*, mlen : UInt64, sk : UInt8*) : Int32
    fun crypto_sign_verify_detached(sig : UInt8*, m : UInt8*, mlen : UInt64, pk : UInt8*) : Int32

    fun crypto_box_keypair(pk : UInt8*, sk : UInt8*) : Int32
    fun crypto_box_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : Int32
    fun crypto_scalarmult(q : UInt8*, n : UInt8*, p : UInt8*) : Int32
    fun crypto_scalarmult_base(q : UInt8*, n : UInt8*) : Int32

    fun sodium_memcmp(b1 : UInt8*, b2 : UInt8*, len : LibC::SizeT) : Int32
    fun sodium_memzero(pnt : Void*, len : LibC::SizeT)

    fun sodium_malloc(size : LibC::SizeT) : Void*
    fun sodium_free(ptr : Void*)
    fun sodium_mprotect_noaccess(ptr : Void*) : Int32
    fun sodium_mprotect_readonly(ptr : Void*) : Int32
    fun sodium_mprotect_readwrite(ptr : Void*) : Int32
  end
end

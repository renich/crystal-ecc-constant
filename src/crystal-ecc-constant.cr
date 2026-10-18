# Constant-time Elliptic Curve Cryptography (Ed25519 and X25519) backed by libsodium secure memory.
module Crystal::Ecc::Constant
  # The current library version.
  VERSION = "0.2.1"
end

require "./crystal-ecc-constant/lib_sodium"
require "./crystal-ecc-constant/types"
require "./crystal-ecc-constant/sodium"
require "./crystal-ecc-constant/secure_memory"
require "./crystal-ecc-constant/ed25519"
require "./crystal-ecc-constant/x25519"

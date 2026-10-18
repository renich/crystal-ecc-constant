===============
Getting Started
===============

Installation
------------

Ensure ``libsodium`` development headers are installed on your system (for example, ``sudo dnf install libsodium-devel`` on Fedora Linux), then add ``crystal-ecc-constant`` to your project's ``shard.yml``:

.. code-block:: yaml

   dependencies:
     crystal-ecc-constant:
       gitlab: renich/crystal-ecc-constant
       version: ~> 0.2.2

Install dependencies:

.. code-block:: bash

   shards install

Basic Usage
-----------

Require the library, initialize ``libsodium``, and perform Ed25519 signing, ``Ed25519ph`` streaming verification, ``crypto_kdf`` subkey derivation, or X25519 Diffie-Hellman key agreement:

.. code-block:: crystal

   require "crystal-ecc-constant"

   # Initialize libsodium (thread-safe and idempotent)
   Crystal::Ecc::Constant::Sodium.init

   # Ed25519 Detached Signing, Ed25519ph Streaming, and Verification
   keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
   begin
     message = "Strictly FIDO2 assertion payload".to_slice
     signature = keypair.sign(message)
     puts keypair.verify(message, signature) # => true

     stream = Crystal::Ecc::Constant::Ed25519PhStream.new
     stream.update("Multi-part ".to_slice).update("payload".to_slice)
     ph_sig = stream.final_sign(keypair)

     verifier = Crystal::Ecc::Constant::Ed25519PhStream.new
     verifier.update("Multi-part payload".to_slice)
     puts verifier.final_verify(keypair.public_key, ph_sig) # => true
   ensure
     keypair.dispose
   end

   # Guarded BLAKE2b Subkey Derivation
   master_key = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Random::Secure.random_bytes(32))
   subkey = Crystal::Ecc::Constant::Kdf.derive_subkey(master_key, 1_u64, "ECC_KDF1", 32)
   subkey.dispose
   master_key.dispose

   # X25519 ECDH Key Exchange with Block-Scoped Consumption
   alice = Crystal::Ecc::Constant::X25519KeyPair.generate
   bob = Crystal::Ecc::Constant::X25519KeyPair.generate
   begin
     alice.diffie_hellman(bob.public_key).consume do |alice_secret|
       bob.diffie_hellman(alice.public_key).consume do |bob_secret|
         puts Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret) # => true
       end
     end
   ensure
     alice.dispose
     bob.dispose
   end

Error Handling
--------------

Catch ``SodiumError`` and ``ArgumentError`` exceptions cleanly:

.. code-block:: crystal

   begin
     Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(Bytes.new(16))
   rescue ex : ArgumentError
     STDERR.puts "Invalid seed size: #{ex.message}"
   rescue ex : Crystal::Ecc::Constant::SodiumError
     STDERR.puts "Cryptographic error: #{ex.message}"
   end

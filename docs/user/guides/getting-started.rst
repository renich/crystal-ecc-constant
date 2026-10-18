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
       version: ~> 0.2.1

Install dependencies:

.. code-block:: bash

   shards install

Basic Usage
-----------

Require the library, initialize ``libsodium``, and perform Ed25519 signing or X25519 Diffie-Hellman key agreement:

.. code-block:: crystal

   require "crystal-ecc-constant"

   # Initialize libsodium (thread-safe and idempotent)
   Crystal::Ecc::Constant::Sodium.init

   # Ed25519 Detached Signing and Verification
   keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
   begin
     message = "Strictly FIDO2 assertion payload".to_slice
     signature = keypair.sign(message)
     puts keypair.verify(message, signature) # => true
   ensure
     keypair.dispose
   end

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

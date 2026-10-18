require "./spec_helper"

describe Crystal::Ecc::Constant do
  describe "Type Design" do
    it "ensures sensitive wrappers use safe class wrappers" do
      (Crystal::Ecc::Constant::PrivateKeyPointer < Reference).should be_true
      (Crystal::Ecc::Constant::Ed25519KeyPair < Reference).should be_true
      (Crystal::Ecc::Constant::X25519KeyPair < Reference).should be_true
      (Crystal::Ecc::Constant::SharedSecret < Reference).should be_true
      (Crystal::Ecc::Constant::PublicKey < Struct).should be_true
      (Crystal::Ecc::Constant::Signature < Struct).should be_true
    end
  end

  describe "PublicKey and Signature Immutability" do
    it "rejects invalid public key sizes" do
      expect_raises(ArgumentError, /Invalid public key size/) do
        Crystal::Ecc::Constant::PublicKey.new(Bytes.new(31))
      end
    end

    it "protects internal bytes against external mutation via to_bytes and bytes" do
      bytes = Bytes.new(32, 7_u8)
      pk = Crystal::Ecc::Constant::PublicKey.new(bytes)
      bytes[0] = 99_u8
      pk.to_bytes[0].should eq(7_u8)

      extracted = pk.to_bytes
      extracted[0] = 42_u8
      pk.to_bytes[0].should eq(7_u8)

      defensive_copy = pk.bytes
      defensive_copy[0] = 0_u8
      pk.bytes[0].should eq(7_u8)
    end

    it "rejects invalid signature sizes" do
      expect_raises(ArgumentError, /Invalid signature size/) do
        Crystal::Ecc::Constant::Signature.new(Bytes.new(63))
      end
    end

    it "protects internal signature bytes against external mutation via to_bytes and bytes" do
      bytes = Bytes.new(64, 5_u8)
      sig = Crystal::Ecc::Constant::Signature.new(bytes)
      bytes[0] = 99_u8
      sig.to_bytes[0].should eq(5_u8)

      extracted = sig.to_bytes
      extracted[0] = 42_u8
      sig.to_bytes[0].should eq(5_u8)

      defensive_copy = sig.bytes
      defensive_copy[0] = 0_u8
      sig.bytes[0].should eq(5_u8)
    end
  end

  describe "Sodium Initialization & Version" do
    it "provides a valid LibSodium version string" do
      Crystal::Ecc::Constant::Sodium.init
      Crystal::Ecc::Constant::Sodium.initialized?.should be_true
      Crystal::Ecc::Constant::Sodium.version.should_not be_empty
    end
  end

  describe "Ed25519 Digital Signatures" do
    it "generates keypair, signs, and verifies correctly" do
      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      begin
        message = "Strictly FIDO2 assertion".to_slice
        signature = keypair.sign(message)

        Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, message, signature).should be_true
        keypair.public_key.verify_ed25519(message, signature).should be_true
        keypair.verify(message, signature).should be_true

        tampered = "Strictly FIDO2 assertioN".to_slice
        Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, tampered, signature).should be_false
        keypair.verify(tampered, signature).should be_false
      ensure
        keypair.dispose
      end
    end

    it "derives deterministic keypairs from a 32-byte seed" do
      seed = Bytes.new(32, 0x42_u8)
      kp1 = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      kp2 = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)

      begin
        kp1.public_key.should eq(kp2.public_key)
        sig1 = kp1.sign("deterministic".to_slice)
        sig2 = kp2.sign("deterministic".to_slice)
        sig1.should eq(sig2)
      ensure
        kp1.dispose
        kp2.dispose
      end
    end

    it "rejects seed with invalid length" do
      expect_raises(ArgumentError, /must be exactly 32 bytes/) do
        Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(Bytes.new(16))
      end
    end

    it "rejects mismatched PrivateKeyPointer size on initialization" do
      pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32))
      bad_sk = Crystal::Ecc::Constant::PrivateKeyPointer.allocate(32) { }
      begin
        expect_raises(ArgumentError, /Invalid Ed25519 private key size/) do
          Crystal::Ecc::Constant::Ed25519KeyPair.new(pk, bad_sk)
        end
      ensure
        bad_sk.dispose
      end
    end

    it "raises when signing with a disposed keypair" do
      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      keypair.dispose

      expect_raises(Crystal::Ecc::Constant::SodiumError, "Key has been disposed") do
        keypair.sign("test".to_slice)
      end
    end
  end

  describe "X25519 Diffie-Hellman Key Exchange" do
    it "performs successful ECDH with block-scoped memory sanitization" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate

      begin
        shared_alice = alice.diffie_hellman(bob.public_key)
        shared_bob = bob.diffie_hellman(alice.public_key)

        matched = false
        shared_alice.consume do |alice_secret|
          shared_bob.consume do |bob_secret|
            matched = Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)
          end
        end

        matched.should be_true
        shared_alice.disposed?.should be_true
        shared_bob.disposed?.should be_true
      ensure
        alice.dispose
        bob.dispose
      end
    end

    it "performs safe value consumption without use-after-free" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate

      begin
        shared = alice.diffie_hellman(bob.public_key)
        secret_copy = shared.consume

        shared.disposed?.should be_true
        shared.consumed?.should be_true
        secret_copy.size.should eq(32)

        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already consumed") do
          shared.consume
        end
      ensure
        alice.dispose
        bob.dispose
      end
    end

    it "derives deterministic X25519 keypairs from seed" do
      seed = Bytes.new(32, 0x11_u8)
      kp1 = Crystal::Ecc::Constant::X25519KeyPair.from_seed(seed)
      kp2 = Crystal::Ecc::Constant::X25519KeyPair.from_seed(seed)

      begin
        kp1.public_key.should eq(kp2.public_key)
      ensure
        kp1.dispose
        kp2.dispose
      end
    end

    it "rejects X25519 seed with invalid length" do
      expect_raises(ArgumentError, /must be exactly 32 bytes/) do
        Crystal::Ecc::Constant::X25519KeyPair.from_seed(Bytes.new(16))
      end
    end

    it "rejects mismatched PrivateKeyPointer size on initialization" do
      pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32))
      bad_sk = Crystal::Ecc::Constant::PrivateKeyPointer.allocate(64) { }
      begin
        expect_raises(ArgumentError, /Invalid X25519 private key size/) do
          Crystal::Ecc::Constant::X25519KeyPair.new(pk, bad_sk)
        end
      ensure
        bad_sk.dispose
      end
    end

    it "raises when performing diffie_hellman with a disposed keypair" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate
      alice.dispose

      begin
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Key has been disposed") do
          alice.diffie_hellman(bob.public_key)
        end
      ensure
        bob.dispose
      end
    end

    it "rejects an all-zero weak public key during diffie_hellman" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      weak_pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32, 0_u8))

      begin
        expect_raises(Crystal::Ecc::Constant::SodiumError, /weak or invalid key/) do
          alice.diffie_hellman(weak_pk)
        end
      ensure
        alice.dispose
      end
    end

    it "raises when consuming a disposed SharedSecret" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate

      begin
        shared1 = alice.diffie_hellman(bob.public_key)
        shared1.dispose
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already disposed") do
          shared1.consume
        end

        shared2 = alice.diffie_hellman(bob.public_key)
        shared2.dispose
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already disposed") do
          shared2.consume(&.size)
        end
      ensure
        alice.dispose
        bob.dispose
      end
    end
  end

  describe "Constant-time equality" do
    it "returns true for identical byte slices" do
      a = "top_secret_data".to_slice
      b = "top_secret_data".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_true
    end

    it "returns false for different bytes of equal size" do
      a = "top_secret_data1".to_slice
      b = "top_secret_data2".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_false
    end

    it "returns false for different lengths" do
      a = "short".to_slice
      b = "much_longer_string".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_false
    end

    it "safely handles empty slices without null pointer FFI crashes" do
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(Bytes.empty, Bytes.empty).should be_true
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(Bytes.empty, "nonempty".to_slice).should be_false
    end
  end

  describe "Adversarial & Concurrency Safety" do
    it "safely handles idempotent dispose without double-free errors" do
      kp = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      kp.dispose
      kp.disposed?.should be_true
      kp.dispose
      kp.disposed?.should be_true
    end

    it "executes concurrent key generations and signatures across fibers without data races" do
      channel = Channel(Bool).new(8)
      8.times do
        spawn do
          key = Crystal::Ecc::Constant::Ed25519KeyPair.generate
          sig = key.sign("concurrent_load".to_slice)
          valid = Crystal::Ecc::Constant::Sodium.verify_ed25519(key.public_key, "concurrent_load".to_slice, sig)
          key.dispose
          channel.send(valid)
        end
      end

      8.times do
        result = channel.receive
        result.should be_true
      end
    end
  end
end

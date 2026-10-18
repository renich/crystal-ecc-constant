require "./spec_helper"

# Verifies [FUNC-001]..[FUNC-005] / [TECH-001]..[TECH-005]
describe Crystal::Ecc::Constant do
  describe "Type Design" do
    it "ensures sensitive wrappers use safe class wrappers" do
      (Crystal::Ecc::Constant::PrivateKeyPointer < Reference).should be_true
      (Crystal::Ecc::Constant::SecureBuffer < Reference).should be_true
      (Crystal::Ecc::Constant::Ed25519KeyPair < Reference).should be_true
      (Crystal::Ecc::Constant::Ed25519PhStream < Reference).should be_true
      (Crystal::Ecc::Constant::X25519KeyPair < Reference).should be_true
      (Crystal::Ecc::Constant::SharedSecret < Reference).should be_true
      (Crystal::Ecc::Constant::PublicKey < Struct).should be_true
      (Crystal::Ecc::Constant::Signature < Struct).should be_true
    end
  end

  describe "PublicKey and Signature Immutability" do
    it "rejects invalid public key and signature sizes" do
      expect_raises(ArgumentError, /Invalid public key size/) { Crystal::Ecc::Constant::PublicKey.new(Bytes.new(31)) }
      expect_raises(ArgumentError, /Invalid signature size/) { Crystal::Ecc::Constant::Signature.new(Bytes.new(63)) }
    end

    it "protects internal bytes against external mutation via to_bytes and bytes" do
      pk_bytes = Bytes.new(32, 7_u8)
      pk = Crystal::Ecc::Constant::PublicKey.new(pk_bytes)
      pk_bytes[0] = 99_u8
      pk.to_bytes[0].should eq(7_u8)
      pk.bytes[0] = 0_u8
      pk.bytes[0].should eq(7_u8)

      sig_bytes = Bytes.new(64, 5_u8)
      sig = Crystal::Ecc::Constant::Signature.new(sig_bytes)
      sig_bytes[0] = 99_u8
      sig.to_bytes[0].should eq(5_u8)
      sig.bytes[0] = 0_u8
      sig.bytes[0].should eq(5_u8)
    end
  end

  describe "Sodium Initialization & Version" do
    it "provides a valid LibSodium version string" do
      Crystal::Ecc::Constant::VERSION.should eq("0.2.2")
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
        Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(keypair.public_key, message, signature).should be_true
        keypair.public_key.verify_ed25519(message, signature).should be_true
        keypair.verify(message, signature).should be_true

        tampered = "Strictly FIDO2 assertioN".to_slice
        keypair.verify(tampered, signature).should be_false
      ensure
        keypair.dispose
      end
    end

    it "derives deterministic keypairs from a 32-byte seed and validates sizes" do
      seed = Bytes.new(32, 0x42_u8)
      kp1 = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      kp2 = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      begin
        kp1.public_key.should eq(kp2.public_key)
        kp1.sign("det".to_slice).should eq(kp2.sign("det".to_slice))
      ensure
        kp1.dispose
        kp2.dispose
      end

      expect_raises(ArgumentError, /must be exactly 32 bytes/) do
        Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(Bytes.new(16))
      end
    end

    it "rejects mismatched PrivateKeyPointer size and disposed key signing" do
      pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32))
      bad_sk = Crystal::Ecc::Constant::PrivateKeyPointer.allocate(32) { }
      begin
        expect_raises(ArgumentError, /Invalid Ed25519 private key size/) do
          Crystal::Ecc::Constant::Ed25519KeyPair.new(pk, bad_sk)
        end
      ensure
        bad_sk.dispose
      end

      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      keypair.dispose
      expect_raises(Crystal::Ecc::Constant::SodiumError, "Key has been disposed") do
        keypair.sign("test".to_slice)
      end
    end
  end

  describe "X25519 Diffie-Hellman Key Exchange" do
    it "performs successful ECDH with block-scoped and copy-on-consume sanitization" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate

      begin
        shared_alice = alice.diffie_hellman(bob.public_key)
        shared_bob = bob.shared_secret(alice.public_key)

        matched = false
        shared_alice.consume do |alice_secret|
          shared_bob.consume do |bob_secret|
            matched = Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)
          end
        end
        matched.should be_true
        shared_alice.disposed?.should be_true
        shared_bob.disposed?.should be_true

        shared_copy = alice.diffie_hellman(bob.public_key)
        secret_copy = shared_copy.consume
        shared_copy.disposed?.should be_true
        shared_copy.consumed?.should be_true
        secret_copy.size.should eq(32)

        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already consumed") do
          shared_copy.consume
        end
      ensure
        alice.dispose
        bob.dispose
      end
    end

    it "derives deterministic X25519 keypairs and validates inputs" do
      seed = Bytes.new(32, 0x11_u8)
      kp1 = Crystal::Ecc::Constant::X25519KeyPair.from_seed(seed)
      kp2 = Crystal::Ecc::Constant::X25519KeyPair.from_seed(seed)
      begin
        kp1.public_key.should eq(kp2.public_key)
      ensure
        kp1.dispose
        kp2.dispose
      end

      expect_raises(ArgumentError, /must be exactly 32 bytes/) do
        Crystal::Ecc::Constant::X25519KeyPair.from_seed(Bytes.new(16))
      end

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

    it "rejects disposed keys, weak peer keys, and disposed SharedSecret consumption" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate
      weak_pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32, 0_u8))

      begin
        expect_raises(Crystal::Ecc::Constant::SodiumError, /weak or invalid key/) do
          alice.diffie_hellman(weak_pk)
        end

        shared = alice.diffie_hellman(bob.public_key)
        shared.dispose
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already disposed") { shared.consume }
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already disposed") { shared.consume(&.size) }

        alice.dispose
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Key has been disposed") do
          alice.diffie_hellman(bob.public_key)
        end
      ensure
        alice.dispose
        bob.dispose
      end
    end
  end

  describe "Constant-time equality & Concurrency" do
    it "compares slices in constant time and handles empty or mismatched slices" do
      Crystal::Ecc::Constant::Sodium.constant_time_equal?("abc".to_slice, "abc".to_slice).should be_true
      Crystal::Ecc::Constant::Sodium.constant_time_equal?("abc".to_slice, "abd".to_slice).should be_false
      Crystal::Ecc::Constant::Sodium.constant_time_equal?("a".to_slice, "ab".to_slice).should be_false
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(Bytes.empty, Bytes.empty).should be_true
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(Bytes.empty, "a".to_slice).should be_false
    end

    it "handles idempotent dispose and concurrent multi-fiber operations" do
      kp = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      kp.dispose
      kp.dispose
      kp.disposed?.should be_true

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
      8.times { channel.receive.should be_true }
    end
  end
end

require "./spec_helper"
require "../src/crystal-ecc-constant"

describe Crystal::Ecc::Constant do
  describe "Type Design (Structs vs Classes)" do
    it "ensures sensitive wrappers use safe class wrappers to avoid double free" do
      # Classes are Reference types in Crystal, which safely share references
      # and allow finalizers for memory safety.
      Crystal::Ecc::Constant::PrivateKeyPointer.new(Pointer(UInt8).null, 0).is_a?(Reference).should be_truthy
      # Note: We use uninitialized here just to check the type without calling a private initialize
      (uninitialized Crystal::Ecc::Constant::Ed25519KeyPair).is_a?(Reference).should be_truthy
      (uninitialized Crystal::Ecc::Constant::X25519KeyPair).is_a?(Reference).should be_truthy
      (uninitialized Crystal::Ecc::Constant::SharedSecret).is_a?(Reference).should be_truthy
      (uninitialized Crystal::Ecc::Constant::PublicKey).is_a?(Struct).should be_truthy
      (uninitialized Crystal::Ecc::Constant::Signature).is_a?(Struct).should be_truthy
    end
  end

  describe "Public Data Types" do
    describe "PublicKey" do
      it "rejects initialization with invalid sizes" do
        expect_raises(ArgumentError, "Invalid public key size") do
          Crystal::Ecc::Constant::PublicKey.new(Bytes.new(31))
        end
        expect_raises(ArgumentError, "Invalid public key size") do
          Crystal::Ecc::Constant::PublicKey.new(Bytes.new(33))
        end
      end

      it "accepts 32 bytes and returns a copy" do
        bytes = Bytes.new(32) { |i| i.to_u8 }
        pk = Crystal::Ecc::Constant::PublicKey.new(bytes)

        # Modify original bytes, ensure PK remains unchanged
        bytes[0] = 99_u8
        pk.to_bytes[0].should eq(0_u8)
      end
    end

    describe "Signature" do
      it "rejects initialization with invalid sizes" do
        expect_raises(ArgumentError, "Invalid signature size") do
          Crystal::Ecc::Constant::Signature.new(Bytes.new(63))
        end
      end

      it "accepts 64 bytes and returns a copy" do
        bytes = Bytes.new(64) { |i| i.to_u8 }
        sig = Crystal::Ecc::Constant::Signature.new(bytes)

        bytes[0] = 99_u8
        sig.to_bytes[0].should eq(0_u8)
      end
    end
  end

  describe "Sodium Initialization" do
    it "initializes libsodium atomically" do
      Crystal::Ecc::Constant::Sodium.init
      Crystal::Ecc::Constant::Sodium.initialized?.should be_true
    end
  end

  describe "Ed25519" do
    it "generates a keypair, signs, and verifies correctly" do
      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      begin
        message = "Test message for signing".to_slice
        signature = keypair.sign(message)

        # Verify
        verified = Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, message, signature)
        verified.should be_true

        # Tampered message
        tampered_msg = "Test message for signing!".to_slice
        tampered_verified = Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, tampered_msg, signature)
        tampered_verified.should be_false
      ensure
        keypair.dispose
      end
    end

    it "signs an empty message correctly" do
      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      begin
        message = Bytes.empty
        signature = keypair.sign(message)
        verified = Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, message, signature)
        verified.should be_true
      ensure
        keypair.dispose
      end
    end

    it "raises when trying to sign with a disposed keypair" do
      keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
      keypair.dispose

      expect_raises(Crystal::Ecc::Constant::SodiumError, "Key pair has been disposed") do
        keypair.sign("test".to_slice)
      end
    end
  end

  describe "X25519 (ECDH)" do
    it "generates keypairs and performs a successful diffie-hellman exchange" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate

      alice_shared_ptr = Pointer(Crystal::Ecc::Constant::SharedSecret).null
      bob_shared_ptr = Pointer(Crystal::Ecc::Constant::SharedSecret).null

      begin
        alice_shared = alice.diffie_hellman(bob.public_key)
        alice_shared_ptr = pointerof(alice_shared)

        bob_shared = bob.diffie_hellman(alice.public_key)
        bob_shared_ptr = pointerof(bob_shared)

        alice_secret = alice_shared.consume
        bob_secret = bob_shared.consume

        # Verify matching secrets using constant_time_equal?
        match = Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)
        match.should be_true

        # Verify SharedSecret can't be consumed twice
        expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already consumed") do
          alice_shared.consume
        end
      ensure
        alice.dispose
        bob.dispose
        alice_shared_ptr.value.dispose if alice_shared_ptr && !alice_shared_ptr.null?
        bob_shared_ptr.value.dispose if bob_shared_ptr && !bob_shared_ptr.null?
      end
    end

    it "raises when trying to diffie_hellman with a disposed keypair" do
      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      bob = Crystal::Ecc::Constant::X25519KeyPair.generate
      alice.dispose

      expect_raises(Crystal::Ecc::Constant::SodiumError, "Key pair has been disposed") do
        alice.diffie_hellman(bob.public_key)
      end
      bob.dispose
    end
  end

  describe "Constant-time equality" do
    it "returns true for equal bytes" do
      a = "secret_data".to_slice
      b = "secret_data".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_true
    end

    it "returns false for different bytes of same length" do
      a = "secret_data".to_slice
      b = "secret_datb".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_false
    end

    it "returns false for different lengths" do
      a = "secret_data".to_slice
      b = "secret".to_slice
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_false
    end

    it "handles empty slices safely" do
      a = Bytes.empty
      b = Bytes.empty
      Crystal::Ecc::Constant::Sodium.constant_time_equal?(a, b).should be_true
    end
  end
end
describe "Adversarial Checks" do
  it "prevents double-free vulnerabilities when instances are assigned/copied" do
    kp1 = Crystal::Ecc::Constant::Ed25519KeyPair.generate
    kp2 = kp1
    kp1.dispose
    # In the previous struct implementation, this caused a segmentation fault
    # Now it should safely do nothing because they share the same disposed object
    kp2.dispose
    Crystal::Ecc::Constant::Sodium.initialized?.should be_true
  end

  it "safely handles early disposal of SharedSecret" do
    alice = Crystal::Ecc::Constant::X25519KeyPair.generate
    bob = Crystal::Ecc::Constant::X25519KeyPair.generate
    shared = alice.diffie_hellman(bob.public_key)

    shared2 = shared
    shared.dispose
    shared2.dispose # Should not crash

    expect_raises(Crystal::Ecc::Constant::SodiumError, "Shared secret already disposed") do
      shared.consume
    end
  end
end

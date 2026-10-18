require "./spec_helper"

# Verifies [FUNC-006] / [TECH-006] and [FUNC-007] / [TECH-005] / [TECH-007]
describe "RFC 8032, RFC 7748, and Project Wycheproof Edge-Case Vectors" do
  describe "RFC 8032 §7.1 Ed25519 Official Vectors" do
    it "matches RFC 8032 §7.1 TEST 1 (empty message)" do
      seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexbytes
      expected_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".hexbytes
      expected_sig = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" \
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
      ).hexbytes

      kp = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      begin
        kp.public_key.to_bytes.should eq(expected_pk)
        sig = kp.sign(Bytes.empty)
        sig.to_bytes.should eq(expected_sig)
        Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(kp.public_key, Bytes.empty, sig).should be_true
      ensure
        kp.dispose
      end
    end

    it "matches RFC 8032 §7.1 TEST 2 (1-byte 0x72 payload)" do
      seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb".hexbytes
      expected_pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c".hexbytes
      expected_sig = (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" \
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
      ).hexbytes
      msg = "72".hexbytes

      kp = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      begin
        kp.public_key.to_bytes.should eq(expected_pk)
        sig = kp.sign(msg)
        sig.to_bytes.should eq(expected_sig)
        kp.verify(msg, sig).should be_true
      ensure
        kp.dispose
      end
    end
  end

  describe "RFC 8032 §7.3 Ed25519ph Official Vector" do
    it "matches RFC 8032 §7.3 pre-hashed streaming vector for 'abc'" do
      seed = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42".hexbytes
      expected_pk = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf".hexbytes
      expected_sig = (
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41" \
        "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
      ).hexbytes

      kp = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
      signer = Crystal::Ecc::Constant::Ed25519PhStream.new
      verifier = Crystal::Ecc::Constant::Ed25519PhStream.new

      begin
        kp.public_key.to_bytes.should eq(expected_pk)
        sig = signer.update("a").update("bc").final_sign(kp)
        sig.to_bytes.should eq(expected_sig)
        verifier.update("abc").final_verify(kp.public_key, sig).should be_true
      ensure
        signer.dispose
        verifier.dispose
        kp.dispose
      end
    end
  end

  describe "RFC 7748 §6.1 X25519 Diffie-Hellman Official Vector" do
    it "computes the exact RFC 7748 §6.1 shared secret inside guarded memory" do
      alice_scalar_bytes = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexbytes
      alice_pk_bytes = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a".hexbytes
      bob_scalar_bytes = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".hexbytes
      bob_pk_bytes = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".hexbytes
      expected_shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742".hexbytes

      alice_sk = Crystal::Ecc::Constant::SecureBuffer.from_bytes(alice_scalar_bytes)
      bob_sk = Crystal::Ecc::Constant::SecureBuffer.from_bytes(bob_scalar_bytes)
      alice = Crystal::Ecc::Constant::X25519KeyPair.new(Crystal::Ecc::Constant::PublicKey.new(alice_pk_bytes), alice_sk)
      bob = Crystal::Ecc::Constant::X25519KeyPair.new(Crystal::Ecc::Constant::PublicKey.new(bob_pk_bytes), bob_sk)

      begin
        alice.shared_secret(bob.public_key).consume do |secret|
          Crystal::Ecc::Constant::Sodium.constant_time_equal?(secret, expected_shared).should be_true
        end
        bob.shared_secret(alice.public_key).consume do |secret|
          Crystal::Ecc::Constant::Sodium.constant_time_equal?(secret, expected_shared).should be_true
        end
      ensure
        alice.dispose
        bob.dispose
      end
    end

    it "matches RFC 7748 §5.2 iterative X25519 vector at 1 and 1,000 iterations" do
      expected_1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079".hexbytes
      expected_1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51".hexbytes
      dummy_pk = Crystal::Ecc::Constant::PublicKey.new(Bytes.new(32))
      u = Bytes.new(32, 0_u8).tap { |b| b[0] = 9_u8 }
      k = u.dup

      1000.times do |iter|
        sk = Crystal::Ecc::Constant::SecureBuffer.from_bytes(k)
        kp = Crystal::Ecc::Constant::X25519KeyPair.new(dummy_pk, sk)
        begin
          next_k = kp.shared_secret(Crystal::Ecc::Constant::PublicKey.new(u)).consume
          u = k
          k = next_k
          k.should eq(expected_1) if iter == 0
        ensure
          kp.dispose
        end
      end
      k.should eq(expected_1000)
    end
  end

  describe "Project Wycheproof Edge-Case Vectors" do
    it "rejects all 8 canonical and high-bit Wycheproof small-order X25519 public keys" do
      low_order_points = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ]

      alice = Crystal::Ecc::Constant::X25519KeyPair.generate
      begin
        low_order_points.each do |hex_point|
          peer_pk = Crystal::Ecc::Constant::PublicKey.new(hex_point.hexbytes)
          expect_raises(Crystal::Ecc::Constant::SodiumError, /weak or invalid key/) do
            alice.shared_secret(peer_pk)
          end
        end
      ensure
        alice.dispose
      end
    end

    it "rejects Wycheproof malleable S >= L and small-order Ed25519 signatures" do
      seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexbytes
      kp = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)

      begin
        # S = L (group order 2^252 + 27742317777372353535851937790883648493) is non-canonical
        malleable_sig_bytes = (
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" \
          "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        ).hexbytes
        malleable_sig = Crystal::Ecc::Constant::Signature.new(malleable_sig_bytes)
        valid = Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(kp.public_key, Bytes.empty, malleable_sig)
        valid.should be_false

        stream = Crystal::Ecc::Constant::Ed25519PhStream.new
        begin
          stream.final_verify(kp.public_key, malleable_sig).should be_false
        ensure
          stream.dispose
        end

        # All-zero small-order R and S signature
        zero_sig = Crystal::Ecc::Constant::Signature.new(Bytes.new(64, 0_u8))
        Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(kp.public_key, Bytes.empty, zero_sig).should be_false
      ensure
        kp.dispose
      end
    end
  end
end

require "./spec_helper"

# Verifies [FUNC-006] / [TECH-006]
describe Crystal::Ecc::Constant::Ed25519PhStream do
  it "uses Reference class semantics for guarded streaming state" do
    (Crystal::Ecc::Constant::Ed25519PhStream < Reference).should be_true
  end

  it "signs and verifies multi-part streaming payloads in guarded memory" do
    keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
    signer = Crystal::Ecc::Constant::Ed25519PhStream.new
    verifier = Crystal::Ecc::Constant::Ed25519PhStream.new
    tampered_verifier = Crystal::Ecc::Constant::Ed25519PhStream.new

    begin
      signer.update("chunk-1:".to_slice).update("chunk-2")
      signature = signer.final_sign(keypair)
      signer.disposed?.should be_true

      verifier.update("chunk-1:").update("chunk-2".to_slice)
      verifier.final_verify(keypair.public_key, signature).should be_true
      verifier.disposed?.should be_true

      tampered_verifier.update("chunk-1:tampered")
      tampered_verifier.final_verify(keypair.public_key, signature).should be_false
      tampered_verifier.disposed?.should be_true
    ensure
      signer.dispose
      verifier.dispose
      tampered_verifier.dispose
      keypair.dispose
    end
  end

  it "enforces RFC 8032 domain separation from single-pass Ed25519" do
    seed = Bytes.new(32, 0x24_u8)
    keypair = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
    stream = Crystal::Ecc::Constant::Ed25519PhStream.new

    begin
      payload = "domain-separated-message".to_slice
      pure_sig = keypair.sign(payload)
      ph_sig = stream.update(payload).final_sign(keypair)

      pure_sig.should_not eq(ph_sig)
      Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(keypair.public_key, payload, pure_sig).should be_true
      Crystal::Ecc::Constant::Ed25519KeyPair.verify_detached(keypair.public_key, payload, ph_sig).should be_false
    ensure
      stream.dispose
      keypair.dispose
    end
  end

  it "rejects operations on a disposed or finalized stream" do
    keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
    stream = Crystal::Ecc::Constant::Ed25519PhStream.new

    begin
      stream.dispose
      stream.disposed?.should be_true

      expect_raises(Crystal::Ecc::Constant::SodiumError, /disposed/) do
        stream.update("data")
      end

      expect_raises(Crystal::Ecc::Constant::SodiumError, /disposed/) do
        stream.final_sign(keypair)
      end

      dummy_sig = Crystal::Ecc::Constant::Signature.new(Bytes.new(64))
      expect_raises(Crystal::Ecc::Constant::SodiumError, /disposed/) do
        stream.final_verify(keypair.public_key, dummy_sig)
      end
    ensure
      keypair.dispose
    end
  end

  it "disposes the streaming state in ensure even if the signing keypair is disposed" do
    keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
    keypair.dispose
    stream = Crystal::Ecc::Constant::Ed25519PhStream.new
    stream.update("payload")

    expect_raises(Crystal::Ecc::Constant::SodiumError, "Key has been disposed") do
      stream.final_sign(keypair)
    end

    stream.disposed?.should be_true
  end

  it "executes concurrent streaming signatures across fibers without data races" do
    channel = Channel(Bool).new(8)
    8.times do |idx|
      spawn do
        kp = Crystal::Ecc::Constant::Ed25519KeyPair.generate
        s_sign = Crystal::Ecc::Constant::Ed25519PhStream.new
        s_ver = Crystal::Ecc::Constant::Ed25519PhStream.new
        begin
          msg = "parallel-stream-#{idx}"
          sig = s_sign.update(msg).final_sign(kp)
          valid = s_ver.update(msg).final_verify(kp.public_key, sig)
          channel.send(valid && s_sign.disposed? && s_ver.disposed?)
        ensure
          s_sign.dispose
          s_ver.dispose
          kp.dispose
        end
      end
    end

    8.times do
      channel.receive.should be_true
    end
  end
end

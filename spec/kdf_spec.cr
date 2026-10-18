require "./spec_helper"

# Verifies [FUNC-007] / [TECH-007]
describe Crystal::Ecc::Constant::Kdf do
  it "derives deterministic subkeys into guarded SecureBuffer memory" do
    raw_master = Bytes.new(32, &.to_u8)
    master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(raw_master)
    sub1 = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 1_u64, "ECC_KDF1", 32)
    sub2 = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 1_u64, "ECC_KDF1", 32)
    sub_diff_id = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 2_u64, "ECC_KDF1", 32)
    sub_diff_ctx = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 1_u64, "ECC_KDF2", 32)

    begin
      sub1.size.should eq(32)
      sub1.with_bytes do |bytes1|
        sub2.with_bytes do |bytes2|
          Crystal::Ecc::Constant::Sodium.constant_time_equal?(bytes1, bytes2).should be_true
        end
        sub_diff_id.with_bytes do |bytes_diff_id|
          Crystal::Ecc::Constant::Sodium.constant_time_equal?(bytes1, bytes_diff_id).should be_false
        end
        sub_diff_ctx.with_bytes do |bytes_diff_ctx|
          Crystal::Ecc::Constant::Sodium.constant_time_equal?(bytes1, bytes_diff_ctx).should be_false
        end
      end
    ensure
      sub1.dispose
      sub2.dispose
      sub_diff_id.dispose
      sub_diff_ctx.dispose
      master.dispose
    end
  end

  it "supports boundary subkey sizes of 16 and 64 bytes" do
    master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Bytes.new(32, 0x5A_u8))
    sub16 = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 10_u64, "BOUNDARY", 16)
    sub64 = Crystal::Ecc::Constant::Kdf.derive_subkey(master, 10_u64, "BOUNDARY", 64)

    begin
      sub16.size.should eq(16)
      sub64.size.should eq(64)
      sub16.to_bytes.size.should eq(16)
      sub64.to_bytes.size.should eq(64)
    ensure
      sub16.dispose
      sub64.dispose
      master.dispose
    end
  end

  it "raises ArgumentError for invalid master_key size, context bytesize, or subkey_size" do
    bad_master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Bytes.new(16, 1_u8))
    good_master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Bytes.new(32, 1_u8))

    begin
      expect_raises(ArgumentError, /master_key must be exactly 32 bytes/) do
        Crystal::Ecc::Constant::Kdf.derive_subkey(bad_master, 1_u64, "CONTEXT8", 32)
      end

      expect_raises(ArgumentError, /context must be exactly 8 bytes/) do
        Crystal::Ecc::Constant::Kdf.derive_subkey(good_master, 1_u64, "SHORT", 32)
      end

      expect_raises(ArgumentError, /context must be exactly 8 bytes/) do
        Crystal::Ecc::Constant::Kdf.derive_subkey(good_master, 1_u64, "TOO_LONG_9", 32)
      end

      expect_raises(ArgumentError, /subkey_size must be between 16 and 64 bytes/) do
        Crystal::Ecc::Constant::Kdf.derive_subkey(good_master, 1_u64, "CONTEXT8", 15)
      end

      expect_raises(ArgumentError, /subkey_size must be between 16 and 64 bytes/) do
        Crystal::Ecc::Constant::Kdf.derive_subkey(good_master, 1_u64, "CONTEXT8", 65)
      end
    ensure
      bad_master.dispose
      good_master.dispose
    end
  end

  it "raises SodiumError when master_key is disposed" do
    master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Bytes.new(32, 0xAA_u8))
    master.dispose

    expect_raises(Crystal::Ecc::Constant::SodiumError, /disposed/) do
      Crystal::Ecc::Constant::Kdf.derive_subkey(master, 1_u64, "CONTEXT8", 32)
    end
  end

  it "executes concurrent subkey derivations across fibers safely" do
    master = Crystal::Ecc::Constant::SecureBuffer.from_bytes(Bytes.new(32, 0x33_u8))
    channel = Channel(Bool).new(8)

    begin
      8.times do |idx|
        spawn do
          sub = Crystal::Ecc::Constant::Kdf.derive_subkey(master, idx.to_u64, "PARALLEL", 32)
          valid = sub.size == 32 && !sub.disposed?
          sub.dispose
          channel.send(valid && sub.disposed?)
        end
      end

      8.times do
        channel.receive.should be_true
      end
    ensure
      master.dispose
    end
  end
end

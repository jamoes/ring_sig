require 'spec_helper'

describe RingSig::Signature do
  group = ECDSA::Group::Secp256k1
  hasher = RingSig::Hasher::Secp256k1_Sha256
  signature = RingSig::Signature.new(group.generator, [10], [20], hasher)
  sig_hex = '302d04210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798300302010a3003020114'
  sig_der = "0-\x04!\x02y\xBEf~\xF9\xDC\xBB\xACU\xA0b\x95\xCE\x87\v\a\x02\x9B\xFC\xDB-\xCE(\xD9Y\xF2\x81[\x16\xF8\x17\x980\x03\x02\x01\n0\x03\x02\x01\x14".force_encoding('binary')

  it 'has the right key_image' do
    expect(signature.key_image).to eq group.generator
  end

  it 'has the right c_array' do
    expect(signature.c_array).to contain_exactly 10
  end

  it 'has the right r_array' do
    expect(signature.r_array).to contain_exactly 20
  end

  it 'has the right components' do
    expect(signature.components).to eq group.generator.coords + [10, 20]
  end

  describe '#to_hex' do
    it 'converts to hex correctly' do
      expect(signature.to_hex).to eq sig_hex
    end
  end

  describe '#to_der' do
    it 'converts to der correctly' do
      expect(signature.to_der).to eq sig_der
    end
  end

  describe '#from_hex' do
    it 'converts from hex correctly' do
      expect(RingSig::Signature.from_hex(sig_hex, hasher).components).to eq signature.components
    end
  end

  describe '#from_der' do
    it 'converts from der correctly' do
      expect(RingSig::Signature.from_der(sig_der, hasher).components).to eq signature.components
    end
  end
end

require 'spec_helper'

describe "RSA key generation" do
  it "should generate a key" do
    keypair = Gibberish::RSA.generate_keypair
    keypair.should be_instance_of(Gibberish::RSA::KeyPair)
  end

  it "should generate a key with custom bits" do
    keypair = Gibberish::RSA.generate_keypair(1024)
    keypair.should be_instance_of(Gibberish::RSA::KeyPair)
  end

  it "should answer to public and private key methods" do
    keypair = Gibberish::RSA.generate_keypair(1024)
    keypair.should be_instance_of(Gibberish::RSA::KeyPair)
    keypair.public_key.should_not be_nil
    keypair.private_key.should_not be_nil
  end

end

describe "RSA" do
  before do
    k = Gibberish::RSA.generate_keypair(1024)
    @cipher = Gibberish::RSA.new(k.public_key, k.private_key)
    @pub_cipher = Gibberish::RSA.new(k.public_key, k.private_key)
  end

  it "should encrypt/decrypt with a keypair" do
    encrypted = @cipher.encrypt("Some data")
    p encrypted
    decrypted = @cipher.decrypt(encrypted)
    encrypted.should match(/^[a-zA-Z0-9\+\\\n=]+$/) # Be base64
    decrypted.should eql("Some data")
  end

  it "should work without private key" do
    enc = @pub_cipher.encrypt("Some data")
    enc.should_not be_nil
  end

end

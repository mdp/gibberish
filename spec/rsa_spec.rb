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
    @cipher = Gibberish::RSA.new(k.private_key)
    @pub_cipher = Gibberish::RSA.new(k.public_key)
  end

  it "should encrypt/decrypt with a keypair" do
    encrypted = @cipher.encrypt("Some data")
    decrypted = @cipher.decrypt(encrypted)
    encrypted.should match(/^[a-zA-Z0-9\+\/\n=]+$/) # Be base64
    decrypted.should eql("Some data")
  end

  it "should work without private key" do
    enc = @pub_cipher.encrypt("Some data")
    enc.should match(/^[a-zA-Z0-9\+\/\n=]+$/) # Be base64
  end

end

describe "OpenSSL interop" do

  before :all do
    @private_key = File.read('spec/openssl/private.pem')
    @public_key = File.read('spec/openssl/public.pem')
    keypair = Gibberish::RSA.generate_keypair(1024)
    keypair.passphrase = "p4ssw0rd"
    tmp_file = "/tmp/gibberish-spec-#{Time.now.to_i}#{rand(100)}"
    @pub_key_file = "#{tmp_file}-pub.pem"
    @priv_key_file = "#{tmp_file}-priv.pem"
    File.open(@pub_key_file, 'w') {|f| f.write(keypair.private_key) }
    File.open(@priv_key_file, 'w') {|f| f.write(keypair.public_key) }
  end

  it "should decode with an OpenSSL generated private key" do
    # openssl genrsa -des3 -out private.pem 2048
    # openssl rsa -in private.pem -out public.pem -outform PEM -pubout
    # openssl rsautl -encrypt -inkey public.pem -pubin -in plaintext.txt -out plaintext.crypted
    cipher = Gibberish::RSA.new(@private_key, 'p4ssw0rd')
    cipher.decrypt(File.read('spec/openssl/plaintext.crypted'), :binary => true).should eql(File.read('spec/openssl/plaintext.txt'))
  end

  it "should encode an OpenSSL compatible format" do
  end

end

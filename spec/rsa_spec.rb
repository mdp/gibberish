require 'spec_helper'

describe "RSA key generation" do
  it "should generate a key" do
    keypair = Gibberish::RSA.generate_keypair
    keypair.must_be_instance_of(Gibberish::RSA::KeyPair)
  end

  it "should generate a key with custom bits" do
    keypair = Gibberish::RSA.generate_keypair(1024)
    keypair.must_be_instance_of(Gibberish::RSA::KeyPair)
  end

  it "should answer to public and private key methods" do
    keypair = Gibberish::RSA.generate_keypair(1024)
    keypair.must_be_instance_of(Gibberish::RSA::KeyPair)
    keypair.public_key.wont_be_nil
    keypair.private_key.wont_be_nil
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
    encrypted.must_match(/^[a-zA-Z0-9\+\/\n=]+$/) # Be base64
    decrypted.must_equal("Some data")
  end

  it "should work without private key" do
    enc = @pub_cipher.encrypt("Some data")
    enc.must_match(/^[a-zA-Z0-9\+\/\n=]+$/) # Be base64
  end

end

describe "OpenSSL interop" do

  before do
    @ossl_private_key = File.read('spec/openssl/private.pem')
    @ossl_public_key = File.read('spec/openssl/public.pem')
    @keypair = Gibberish::RSA.generate_keypair(1024)
    @keypair.passphrase = "p4ssw0rd"
    tmp_file = "/tmp/gibberish-spec"
    @pub_key_file = "#{tmp_file}-pub.pem"
    @priv_key_file = "#{tmp_file}-priv.pem"
    File.open(@pub_key_file, 'w') {|f| f.write(@keypair.public_key) }
    File.open(@priv_key_file, 'w') {|f| f.write(@keypair.private_key) }
  end

  it "should decode with an OpenSSL generated private key" do
    # openssl genrsa -des3 -out private.pem 2048
    # openssl rsa -in private.pem -out public.pem -outform PEM -pubout
    # openssl rsautl -encrypt -inkey public.pem -pubin -in plaintext.txt -out plaintext.crypted
    cipher = Gibberish::RSA.new(@ossl_private_key, 'p4ssw0rd')
    cipher.decrypt(File.read('spec/openssl/plaintext.crypted'), :binary => true).must_equal(File.read('spec/openssl/plaintext.txt'))
  end

  it "should encode an OpenSSL compatible format" do
    # openssl rsautl -decrypt -inkey /tmp/gibberish-spec-priv.pem -in /tmp/gibberish-spec-test.crypted
    cipher = Gibberish::RSA.new(@keypair.public_key)
    tmp_crypt_file = '/tmp/gibberish-spec-test.crypted'
    File.open(tmp_crypt_file, 'w') {|f| f.write(cipher.encrypt("secret text", :binary => true))}
    # `openssl rsautl -decrypt -inkey /tmp/gibberish-spec-priv.pem -in /tmp/gibberish-spec-test.crypted`
  end

end

# -*- encoding: utf-8 -*-
require 'spec_helper'
require 'tempfile'

describe "the sjcl compatible implementation of aes" do

  describe "decryption" do

    before do
      @cipher = Gibberish::AES.new("s33krit")
    end
    it "should decrypt gcm encoded text from SJCL" do
      # With a 64bit authentication tag
      json = '{"iv":"pO1RiSKSfmlLPMIS","v":1,"iter":1000,"ks":128,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"BC60XoGJqnY=","ct":"Jgm8bExXvpbEDxOxFDroBuFmczMlfF4G"}'
      @cipher.decrypt(json).must_equal("This is a secret");
      # With a 96bit authentication tag
      json = '{"iv":"6ru5wmyPl2hfhMmb","v":1,"iter":1000,"ks":128,"ts":96,"mode":"gcm","adata":"","cipher":"aes","salt":"KhrgNREkjN4=","ct":"/0LMJz7pYDXSdFa+x3vL7uc46Nz7y5kV9DhEBQ=="}'
      @cipher.decrypt(json).must_equal("This is a secret");
      # With a 128bit authentication tag
      json = '{"iv":"S79wFwpjbSMz1FSB","v":1,"iter":1000,"ks":128,"ts":128,"mode":"gcm","adata":"","cipher":"aes","salt":"KhrgNREkjN4=","ct":"j8pJmmilaJ6We2fEq/NvAxka4Z70F7IEK/m9/y3hHoo="}'
      @cipher.decrypt(json).must_equal("This is a secret");
    end
    it "should include the adata with the plaintext" do
      json = '{"iv":"w9Iugnn0HztMpm+y","v":1,"iter":1000,"ks":128,"ts":64,"mode":"gcm","adata":"123abc","cipher":"aes","salt":"Sw6NOinzVZ8=","ct":"djCIRln1PbuiLEkMb2AJZdT/"}'
      plaintext = @cipher.decrypt(json)
      plaintext.must_equal("plain text")
      plaintext.adata.must_equal("123abc")
    end
    describe "exceptions" do
      it "should check the iterations length before attempting to decrypt" do
        json = '{"iv":"S79wFwpjbSMz1FSB","v":1,"iter":1000000,"ks":128,"ts":128,"mode":"gcm","adata":"","cipher":"aes","salt":"KhrgNREkjN4=","ct":"j8pJmmilaJ6We2fEq/NvAxka4Z70F7IEK/m9/y3hHoo="}'
        e = assert_raises(Gibberish::AES::SJCL::CipherOptionsError) { @cipher.decrypt(json) }
        assert_match(/Iteration count/, e.message)
      end
      it "should only allow authenticated modes" do
        json = '{"iv":"6ru5wmyPl2hfhMmb","v":1,"iter":1000,"ks":128,"ts":96,"mode":"cbc","adata":"","cipher":"aes","salt":"KhrgNREkjN4=","ct":"/0LMJz7pYDXSdFa+x3vL7uc46Nz7y5kV9DhEBQ=="}'
        e = assert_raises(Gibberish::AES::SJCL::CipherOptionsError) { @cipher.decrypt(json) }
        assert_equal("Mode 'cbc' not supported", e.message)
      end
      it "should fail gracefully when attempting to decrypt an SJCL generated ciphertext with a >12 byte IV" do
        json = '{"iv":"fGuapJg66vk0eNNyLHUk1w==","v":1,"iter":1000,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","salt":"GRywsuW0M8E=","ct":"MUq4sLzEHtnUy2nTF8NEJQ=="}'
        e = assert_raises(Gibberish::AES::SJCL::CipherOptionsError) { @cipher.decrypt(json) }
        assert_match(/Initialization vector/, e.message)
      end
      it "should fail if the password is incorrect" do
        json = '{"iv":"ovFbwlWH+tTHFORl","v":1,"iter":1000,"ks":128,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"ib5/ig2qqL8=","ct":"ruxTz/VWArVfte4qzUwF/z74"}'
        assert_raises(Gibberish::AES::SJCL::DecryptionError) { @cipher.decrypt(json) }
      end
      it "should fail if the adata has be modified" do
        json = '{"iv":"S79wFwpjbSMz1FSB","v":1,"iter":1000,"ks":128,"ts":128,"mode":"gcm","adata":"foo","cipher":"aes","salt":"KhrgNREkjN4=","ct":"j8pJmmilaJ6We2fEq/NvAxka4Z70F7IEK/m9/y3hHoo="}'
        assert_raises(Gibberish::AES::SJCL::DecryptionError) {
          @cipher.decrypt(json)
        }
      end
    end
  end

  describe "encryption" do

    it "should encrypt text" do
      @cipher = Gibberish::AES.new("s33krit")
      plaintext = "This is some text, and some UTF-8 中华人民共和"
      ciphertext = @cipher.encrypt(plaintext)
      @cipher.decrypt(ciphertext).must_equal(plaintext);
    end

    it "should allow users to override the number of iterations" do
      @cipher = Gibberish::AES.new("s33krit", {iter: 10_000})
      plaintext = "This is some text"
      ciphertext = @cipher.encrypt(plaintext)
      JSON.parse(ciphertext)["iter"].must_equal(10_000)
      @cipher.decrypt(ciphertext).must_equal(plaintext);
    end

    it "should set the correct JSON attributes in the ciphertext" do
      @cipher = Gibberish::AES.new("s33krit")
      plaintext = "This is some text"
      ciphertext = JSON.parse(@cipher.encrypt(plaintext))
      ciphertext["iter"].must_equal(100_000)
      ciphertext["v"].must_equal(1)
      ciphertext["ks"].must_equal(256)
      ciphertext["ts"].must_equal(96)
      ciphertext["mode"].must_equal("gcm")
      ciphertext["cipher"].must_equal("aes")
    end

  end
end

describe "the openssl command line compatible aes cipher" do

  before do
    @cipher = Gibberish::AES::LegacyOpenSSL.new("password")
  end

  it "should encrypt text and be compatible with OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    encrypted = @cipher.e(secret_text)
    from_openssl = `echo "#{encrypted}" | openssl enc -d -aes-256-cbc -a -k password`
    from_openssl.must_equal(secret_text)
  end

  it "should encrypt file and be compatible with OpenSSL CLI" do
    source_file_path = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    @cipher.ef(source_file_path, encrypted_file.path)
    decrypted_file = Tempfile.new('secret.txt')
    `openssl aes-256-cbc -d -in #{encrypted_file.path} -out #{decrypted_file.path} -k password`
    FileUtils.cmp(source_file_path, decrypted_file.path).must_equal(true)
  end

  it "when salt is not specified, encrypted text from repeated calls should not be the same" do
    secret_text = "Made with Gibberish"
    encrypted1 = @cipher.e(secret_text)
    encrypted2 = @cipher.e(secret_text)
    encrypted1.wont_equal(encrypted2)
  end

  it "when salt is specified, encrypted text from repeated calls (with same salt) be the same" do
    secret_text = "Made with Gibberish"
    salt = 'NaClNaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    encrypted2 = @cipher.e(secret_text, {:salt => salt})
    encrypted1.must_equal(encrypted2)
  end

  it "when supplied salt is too long, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 'NaClNaClNaClNaClNaClNaClNaClNaClNaClNaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).must_equal(secret_text)
  end

  it "when supplied salt is too short, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 'NaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).must_equal(secret_text)
  end

  it "when number is supplied for salt, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 42
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).must_equal(secret_text)
  end

  it "when idiotic value is supplied for salt, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = {:whoknew => "I'm an idiot"}
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).must_equal(secret_text)
  end

  it "should decrypt base64 encoded data from the OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    from_openssl = `echo #{secret_text} | openssl enc -aes-256-cbc -a -k password`
    decrypted_text = @cipher.d(from_openssl).chomp
    decrypted_text.must_equal(secret_text)
  end

  it "should decrypt file encrypted with OpenSSL CLI" do
    source_file_path = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    `openssl aes-256-cbc -salt -in #{source_file_path} -out #{encrypted_file.path} -k password`
    decrypted_file = Tempfile.new('secret.txt')
    @cipher.df(encrypted_file.path, decrypted_file.path)
    FileUtils.cmp(source_file_path, decrypted_file.path).must_equal(true)
  end

  it "should throw correct exception when decryption string is too short" do
    assert_raises(ArgumentError) {@cipher.d("short")}
  end

  describe 'stream encryption' do

    it 'encrypts a file' do
      File.open('spec/openssl/plaintext.txt', 'rb') do |in_file|
        File.open(Tempfile.new('gib'), 'wb') do |enc_file|
          @cipher.encrypt_stream in_file, enc_file, salt: 'SOMESALT'
          File.read(enc_file.path).must_equal(File.read('spec/openssl/plaintext.aes'))
        end
      end
    end

    it 'decrypts a file' do
      File.open('spec/openssl/plaintext.aes', 'rb') do |in_file|
        File.open(Tempfile.new('gib'), 'wb') do |dec_file|
          @cipher.decrypt_stream in_file, dec_file
          File.read(dec_file.path).must_equal(File.read('spec/openssl/plaintext.txt'))
        end
      end
    end

  end

end

require 'spec_helper'
require 'tempfile'

describe "the aes cipher" do

  before do
    @cipher = Gibberish::AES.new("password")
  end

  it "should encrypt text and be compatible with OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    encrypted = @cipher.e(secret_text)
    from_openssl = `echo "#{encrypted}" | openssl enc -d -aes-256-cbc -a -k password`
    from_openssl.must_equal(secret_text)
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

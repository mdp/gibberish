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
    it "should check the options before attempting to decrypt" do
      json = '{"iv":"S79wFwpjbSMz1FSB","v":1,"iter":1000000,"ks":128,"ts":128,"mode":"gcm","adata":"","cipher":"aes","salt":"KhrgNREkjN4=","ct":"j8pJmmilaJ6We2fEq/NvAxka4Z70F7IEK/m9/y3hHoo="}'
      assert_raises(Gibberish::AES::SJCL::CipherOptionsError) {
        @cipher.decrypt(json).must_equal("This is a secret");
      }
    end
  end

  describe "encryption" do

    before do
      @cipher = Gibberish::AES.new("s33krit")
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

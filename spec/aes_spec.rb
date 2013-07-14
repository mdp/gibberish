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

  it "should encrypt file and be compatible with OpenSSL CLI" do
    source_file = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    @cipher.ef(source_file, encrypted_file)
    decrypted_file = Tempfile.new('secret.txt')
    `openssl aes-256-cbc -d -in #{encrypted_file.path} -out #{decrypted_file.path} -k password`
    FileUtils.cmp(source_file, decrypted_file).must_equal(true)
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
    source_file = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    `openssl aes-256-cbc -salt -in #{source_file} -out #{encrypted_file.path} -k password`
    decrypted_file = Tempfile.new('secret.txt')
    @cipher.df(encrypted_file, decrypted_file)
    FileUtils.cmp(source_file, decrypted_file).must_equal(true)
  end

end

require 'spec_helper'

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

  it "should decrypt base64 encoded data from the OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    from_openssl = `echo #{secret_text} | openssl enc -aes-256-cbc -a -k password`
    decrypted_text = @cipher.d(from_openssl).chomp
    decrypted_text.must_equal(secret_text)
  end

end

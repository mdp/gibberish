require 'spec_helper'

describe "HMAC" do

  it "should hopefully work" do
    Gibberish::HMAC("password", "data").must_equal("08d13c72bed7ace5efadc09df109a78a5d713097")
  end

  it "should work with OpenSSL HMAC" do
    hmac = Gibberish::HMAC("password", "data\n")
    o_hmac = `echo "data" | openssl dgst -sha1 -hmac 'password'`
    hmac.must_equal(o_hmac.chomp)
  end

end

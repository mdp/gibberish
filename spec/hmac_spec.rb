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

  it "should hopefully work for sha224" do
    Gibberish::HMAC("password", "data", :digest => :sha224).must_equal(
      "f66aa39e91d003f7d3fc1205f77bd4947af51735a49e197fbd478728")
  end

  it "should work with OpenSSL HMAC for sha224" do
    hmac = Gibberish::HMAC("password", "data\n", :digest => :sha224)
    o_hmac = `echo "data" | openssl dgst -sha224 -hmac 'password'`
    hmac.must_equal(o_hmac.chomp)
  end

  it "should hopefully work for sha256" do
    Gibberish::HMAC("password", "data", :digest => :sha256).must_equal(
      "cccf6f0334130a7010d62332c75b53e7d8cea715e52692b06e9cd41b05644be3")
  end

  it "should work with OpenSSL HMAC for sha256" do
    hmac = Gibberish::HMAC("password", "data\n", :digest => :sha256)
    o_hmac = `echo "data" | openssl dgst -sha256 -hmac 'password'`
    hmac.must_equal(o_hmac.chomp)
  end

  it "should hopefully work for sha384" do
    Gibberish::HMAC("password", "data", :digest => :sha384).must_equal(
      "2ed475691214fb85d086577d8d525c609b92520ebd793a74856b3ffd8d3477eaaf0b06ef9e06c8aa81cf29f95078aca6")
  end

  it "should work with OpenSSL HMAC for sha384" do
    hmac = Gibberish::HMAC("password", "data\n", :digest => :sha384)
    o_hmac = `echo "data" | openssl dgst -sha384 -hmac 'password'`
    hmac.must_equal(o_hmac.chomp)
  end

  it "should hopefully work for sha512" do
    Gibberish::HMAC("password", "data", :digest => :sha512).must_equal("abf85192282b501874f4803ea08672f2c9d6e656c57801023a0b1f4dd9492ba960efdb560a8618ec783327d6dc31577422651a4cf7eaf722d2caefbc04038c6e")
  end

  it "should work with OpenSSL HMAC for sha512" do
    hmac = Gibberish::HMAC("password", "data\n", :digest => :sha512)
    o_hmac = `echo "data" | openssl dgst -sha512 -hmac 'password'`
    hmac.must_equal(o_hmac.chomp)
  end

end

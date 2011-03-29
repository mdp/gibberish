require 'spec_helper'

describe "A variety of digest methods" do

  it "should work with MD5" do
    Gibberish::MD5("password").should eql("5f4dcc3b5aa765d61d8327deb882cf99")
  end

  it "should work with SHA1" do
    Gibberish::SHA1("password").should eql("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
  end

  it "should work with SHA256" do
    Gibberish::SHA256("password").should eql("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
  end

end

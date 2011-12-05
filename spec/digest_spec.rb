require 'spec_helper'

describe "A variety of digest methods" do

  it "should work with MD5" do
    Gibberish::MD5("password").must_equal("5f4dcc3b5aa765d61d8327deb882cf99")
  end

  it "should work with SHA1" do
    Gibberish::SHA1("password").must_equal("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
  end

  it "should work with SHA224" do
    Gibberish::SHA224("password").must_equal("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01")
  end

  it "should work with SHA256" do
    Gibberish::SHA256("password").must_equal("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
  end

  it "should work with SHA384" do
    Gibberish::SHA384("password").must_equal("a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7")
  end

  it "should work with SHA512" do
    Gibberish::SHA512("password").must_equal("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86")
  end

end

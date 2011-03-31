require 'spec_helper'

describe "HMAC" do

  it "should hopefully work" do
    Gibberish::HMAC("password", "data").must_equal("08d13c72bed7ace5efadc09df109a78a5d713097")
  end

end

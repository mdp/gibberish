module Gibberish
  # Allows for the simple digest of data, supports MD5, SHA1, and SHA256
  #
  # ## Examples
  #
  #     Gibberish::MD5("data") #=> 8d777f385d3dfec8815d20f7496026dc
  #     Gibberish::SHA1("data") #=> a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd
  #     Gibberish::SHA256("data") #=> 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
  #
  class Digest

    def self.sha1(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::SHA1.digest(val)
      else
        OpenSSL::Digest::SHA1.hexdigest(val)
      end
    end

    def self.sha256(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::SHA256.digest(val)
      else
        OpenSSL::Digest::SHA256.hexdigest(val)
      end
    end

    def self.md5(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::MD5.digest(val)
      else
        OpenSSL::Digest::MD5.hexdigest(val)
      end
    end
  end

  def self.SHA1(val, opts={})
    Digest.sha1(val,opts)
  end

  def self.SHA256(val, opts={})
    Digest.sha256(val,opts)
  end

  def self.MD5(val, opts={})
    Digest.md5(val,opts)
  end

end

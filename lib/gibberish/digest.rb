module Gibberish
  class Digest

    def self.sha1(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::SHA1.hexdigest(val)
      else
        OpenSSL::Digest::SHA1.digest(val)
      end
    end

    def self.sha256(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::SHA265.hexdigest(val)
      else
        OpenSSL::Digest::SHA265.digest(val)
      end
    end

    def self.md5(val, opts={})
      if opts[:binary]
        OpenSSL::Digest::MD5.hexdigest(val)
      else
        OpenSSL::Digest::MD5.digest(val)
      end
    end
  end

  def SHA1(val, opts={})
    Digest.sha1(val,opts)
  end

  def SHA256(val, opts={})
    Digest.sha256(val,opts)
  end

  def MD5(val, opts={})
    Digest.MD5(val,opts)
  end

end

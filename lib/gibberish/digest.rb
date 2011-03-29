module Gibberish
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

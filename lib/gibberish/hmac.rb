module Gibberish
  class HMAC
    DIGEST = {
      :sha1 => OpenSSL::Digest::Digest.new('sha1'),
      :sha256 => OpenSSL::Digest::Digest.new('sha256')
    }

    def self.digest(key, data, opts={})
      digest_type = opts[:digest] || :sha1
      if opts[:binary]
        OpenSSL::HMAC.digest(DIGEST[digest_type], key, data)
      else
        OpenSSL::HMAC.hexdigest(DIGEST[digest_type], key, data)
      end
    end
  end

  def HMAC(key, data, opts={})
    Giberish::HMAC.digest(key, data, opts)
  end
end

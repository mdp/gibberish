module Gibberish
  # Easy to use HMAC, defaults to SHA1
  #
  # ## Example
  #
  #     Gibberish::HMAC('key', 'data') #=> 104152c5bfdca07bc633eebd46199f0255c9f49d
  #     Gibberish::HMAC('key', 'data', :digest => :sha256)
  #       #=> 5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0
  #
  # ## OpenSSL CLI Interop
  #
  #     echo -n "stuff" | openssl dgst -sha1 -hmac 'password'
  #
  # is the same as
  #
  #     Gibberish::HMAC('password', 'stuff')
  #
  class HMAC
    DIGEST = {
      :sha1 => OpenSSL::Digest::Digest.new('sha1'),
      :sha256 => OpenSSL::Digest::Digest.new('sha256')
    }

    # Returns the HMAC for the key and data
    #
    # Shorcut alias: Gibberish::HMAC(key, data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Hash] options
    # @option opts [Symbol] :digest (:sha1) the digest to encode with
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.digest(key, data, opts={})
      data = data.to_s
      digest_type = opts[:digest] || :sha1
      if opts[:binary]
        OpenSSL::HMAC.digest(DIGEST[digest_type], key, data)
      else
        OpenSSL::HMAC.hexdigest(DIGEST[digest_type], key, data)
      end
    end
  end

  def self.HMAC(key, data, opts={})
    Gibberish::HMAC.digest(key, data, opts)
  end
end

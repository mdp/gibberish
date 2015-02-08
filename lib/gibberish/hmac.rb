module Gibberish
  # Easy to use HMAC
  #
  # ## Example
  #
  #     Gibberish::HMAC256('key', 'data')
  #       #=> 5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0
  #     Gibberish::HMAC1('key', 'data') # SHA1
  #     #=> 104152c5bfdca07bc633eebd46199f0255c9f49d
  #     Gibberish::HMAC224('key', 'data') # SHA224
  #       #=> 19424d4210e50d7a4521b5f0d54b4b0cff3060deddccfd894fda5b3b
  #     Gibberish::HMAC384('key', 'data') # SHA384
  #       #=> c5f97ad9fd1020c174d7dc02cf83c4c1bf15ee20ec555b690ad58e62da8a00ee
  #           44ccdb65cb8c80acfd127ebee568958a
  #     Gibberish::HMAC512('key', 'data') # SHA512
  #       #=> 3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253c
  #           b52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58
  #
  # ## OpenSSL CLI Interop
  #
  #     echo -n "stuff" | openssl dgst -sha256 -hmac 'password'
  #
  # is the same as
  #
  #     Gibberish::HMAC256('password', 'stuff')
  #
  class HMAC
    DIGEST = {
      :sha1 => OpenSSL::Digest.new('sha1'),
      :sha224 => OpenSSL::Digest.new('sha224'),
      :sha256 => OpenSSL::Digest.new('sha256'),
      :sha384 => OpenSSL::Digest.new('sha384'),
      :sha512 => OpenSSL::Digest.new('sha512')
    }

    # Returns the HMAC for the key and data
    #
    # Shorcut alias: Gibberish::HMAC(key, data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Symbol] digest
    # @param [Hash] opts
    # @option opts [Symbol] :digest (:sha1) the digest to encode with
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.digest(key, data, digest, opts={})
      data = data.to_s
      if opts[:binary]
        OpenSSL::HMAC.digest(DIGEST[digest], key, data)
      else
        OpenSSL::HMAC.hexdigest(DIGEST[digest], key, data)
      end
    end
  end

  def self.HMAC1(key, data)
    Gibberish::HMAC.digest(key, data, :sha1)
  end

  def self.HMAC224(key, data)
    Gibberish::HMAC.digest(key, data, :sha224)
  end

  def self.HMAC256(key, data)
    Gibberish::HMAC.digest(key, data, :sha256)
  end

  def self.HMAC384(key, data)
    Gibberish::HMAC.digest(key, data, :sha384)
  end

  def self.HMAC512(key, data)
    Gibberish::HMAC.digest(key, data, :sha512)
  end

end

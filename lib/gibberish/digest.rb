module Gibberish
  # Allows for the simple digest of data, supports MD5, SHA1, and SHA256
  #
  # ## Examples
  #
  #     Gibberish::MD5("data") #=> 8d777f385d3dfec8815d20f7496026dc
  #     Gibberish::SHA1("data") #=> a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd
  #     Gibberish::SHA256("data") #=> 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
  #     Gibberish::SHA512("data") #=> 77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876
  #
  # ## OpenSSL CLI Interop
  #
  #     echo -n 'data' | openssl dgst -sha1
  #     echo -n 'data' | openssl dgst -sha256
  #     echo -n 'data' | openssl dgst -sha512
  #     echo -n 'data' | openssl dgst -md5
  #
  # is the same as
  #
  #     Gibberish::SHA1("data")
  #     Gibberish::SHA256("data")
  #     Gibberish::SHA512("data")
  #     Gibberish::MD5("data")
  #
  class Digest

    # Returns the SHA1 digest for the data
    #
    # Shorcut alias: Gibberish::SHA1(data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Hash] options
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.sha1(data, opts={})
      data = data.to_s
      if opts[:binary]
        OpenSSL::Digest::SHA1.digest(data)
      else
        OpenSSL::Digest::SHA1.hexdigest(data)
      end
    end

    # Returns the SHA256 digest for the data
    #
    # Shorcut alias: Gibberish::SHA256(data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Hash] options
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.sha256(data, opts={})
      data = data.to_s
      if opts[:binary]
        OpenSSL::Digest::SHA256.digest(data)
      else
        OpenSSL::Digest::SHA256.hexdigest(data)
      end
    end

    # Returns the SHA512 digest for the data
    #
    # Shorcut alias: Gibberish::SHA512(data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Hash] options
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.sha512(data, opts={})
      data = data.to_s
      if opts[:binary]
        OpenSSL::Digest::SHA512.digest(data)
      else
        OpenSSL::Digest::SHA512.hexdigest(data)
      end
    end

    # Returns the MD5 digest for the data
    #
    # Shorcut alias: Gibberish::MD5(data)
    #
    # @param [String] key
    # @param [#to_s] data
    # @param [Hash] options
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def self.md5(data, opts={})
      data = data.to_s
      if opts[:binary]
        OpenSSL::Digest::MD5.digest(data)
      else
        OpenSSL::Digest::MD5.hexdigest(data)
      end
    end
  end

  def self.SHA1(data, opts={})
    Digest.sha1(data,opts)
  end

  def self.SHA256(data, opts={})
    Digest.sha256(data,opts)
  end

  def self.SHA512(data, opts={})
    Digest.sha512(data,opts)
  end

  def self.MD5(data, opts={})
    Digest.md5(data,opts)
  end

end

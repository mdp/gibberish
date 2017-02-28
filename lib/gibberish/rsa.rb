module Gibberish

  # This wraps the OpenSSL RSA functions
  # Simply instantiate with a public key or private key
  #
  #     cipher = Gibberish::RSA.new(private_key)
  #     enc = cipher.encrypt(data)
  #     dec = cipher.decrypt(enc)
  #
  #     cipher = Gibberish::RSA(public_key)
  #     cipher.decrypt(enc)
  #
  #
  # You can also generate a keypair using Gibberish::RSA.generate_keypair
  #
  #     kp = Gibberish::RSA.generate_keypair(4096)
  #     kp.public_key #=> Outputs a Base64 encoded public key
  #     kp.private_key #=> Outputs the Base64 pem
  #
  #   KeyPair will hand back the private key when passed
  #   to the RSA class.
  #
  #     cipher = Gibberish::RSA.new(kp)
  #
  # ## OpenSSL CLI Interop
  #
  #     openssl rsautl -decrypt -inkey [pem_file] -in [BinaryEncodedCryptedFile]
  #
  # or if you're using the default base64 output, you'll need to decode that first
  #
  #     openssl enc -d -base64 -in [gibberish.crypted] | \
  #     openssl rsautl -decrypt -inkey [pem_file]
  #

  class RSA
    class KeyPair
      def self.generate(bits=2048)
        self.new(OpenSSL::PKey::RSA.generate(bits))
      end

      attr_accessor :passphrase

      def initialize(key)
        @key = key
        @cipher =  OpenSSL::Cipher.new('aes-256-cbc')
      end

      def public_key
        @key.public_key
      end

      def private_key
        if @passphrase
          @key.to_pem(@cipher, @passphrase)
        else
          @key.to_pem
        end
      end

      def to_s
        private_key
      end

    end

    # Generate an RSA keypair - defaults to 2048 bits
    #
    # @param [Integer] bits
    def RSA.generate_keypair(bits=2048)
      KeyPair.generate(bits)
    end

    # Expects a public key at the minumum
    #
    # @param [#to_s] key public or private
    # @param [String] passphrase to key
    #
    def initialize(key, passphrase=nil)
      @key = OpenSSL::PKey::RSA.new(key.to_s, passphrase)
    end

    # Encrypt data using the key
    #
    # @param [#to_s] data
    # @param [Hash] opts
    # @option opts [Boolean] :binary (false) encode the data in binary, not Base64
    def encrypt(data, opts={})
      data = data.to_s
      enc = @key.public_encrypt(data)
      if opts[:binary]
        enc
      else
        Base64.encode64(enc)
      end
    end

    # Decrypt data using the key
    #
    # @param [#to_s] data
    # @param [Hash] opts
    # @option opts [Boolean] :binary (false) don't decode the data as Base64
    def decrypt(data, opts={})
      data = data.to_s
      raise "No private key set!" unless @key.private?
      unless opts[:binary]
        data = Base64.decode64(data)
      end
      @key.private_decrypt(data)
    end
  end

end

module Gibberish
  class RSA
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

    class KeyPair
      def self.generate(bits=2048)
        self.new(OpenSSL::PKey::RSA.generate(bits))
      end

      def initialize(key)
        @key = key
        @cipher =  OpenSSL::Cipher::Cipher.new('aes-256-cbc')
      end

      def passphrase=(p)
        @passphrase = p
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

    end

    def RSA.generate_keypair(bits=2048)
      KeyPair.generate(bits)
    end

    # Expects a public key at the minumum
    #
    def initialize(key, passphrase=nil)
      @key = OpenSSL::PKey::RSA.new(key, passphrase)
    end

    def encrypt(data, opts={})
      enc = @key.public_encrypt(data)
      if opts[:binary]
        enc
      else
        Base64.encode64(enc)
      end
    end

    def decrypt(data, opts={})
      raise "No private key set!" unless @key.private?
      unless opts[:binary]
        data = Base64.decode64(data)
      end
      @key.private_decrypt(data)
    end
  end

end

module Gibberish
  class RSA

    class KeyPair
      def self.generate(bits=2048)
        self.new(OpenSSL::PKey::RSA.generate(bits))
      end

      def initialize(key)
        @key = key
      end

      def public_key
        @key.public_key
      end

      def private_key
        @key.to_pem
      end

    end

    def RSA.generate_keypair(bits=2048)
      KeyPair.generate(bits)
    end

    # Expects a public key at the minumum
    #
    def initialize(public_key, private_key=nil)
      @pub_key = OpenSSL::PKey::RSA.new(public_key)
      @priv_key = OpenSSL::PKey::RSA.new(private_key)
    end

    def encrypt(data, opts={})
      enc = @pub_key.public_encrypt(data)
      if opts[:binary]
        enc
      else
        Base64.encode64(enc)
      end
    end

    def decrypt(data, opts={})
      raise "No private key set!" unless @priv_key
      unless opts[:binary]
        data = Base64.decode64(data)
      end
      @priv_key.private_decrypt(data)
    end
  end

end

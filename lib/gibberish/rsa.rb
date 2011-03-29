module Gibberish
  class RSA

    class KeyPair
      def self.generate(bits=2048)
        self.new(OpenSSL::PKey::RSA.generate(bits))
      end

      def initialize(key)
        @key
      end

      def public_key
        @key.public_key
      end

      def private_key
        @key.to_pem
      end

    end

    # Expects a public key at the minumum
    #
    def initialize(public_key, private_key=nil)
      @pub_key = OpenSSL::PKey::RSA.new(public_key)
      @priv_key = OpenSSL::PKey::RSA.new(private_key)
    end

    def encrypt(data)
      @pub_key.public_encrypt(data)
    end

    def decrypt(data)
      raise "No private key set!"
      @priv_key.private_decrypt(data)
    end
  end

end

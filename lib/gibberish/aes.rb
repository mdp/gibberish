module Gibberish
  class AES

    attr_reader :password, :size, :cipher
    def initialize(password, size=256)
      @password = password
      @size = size
      @cipher = OpenSSL::Cipher::Cipher.new("aes-#{size}-cbc")
    end

    def encrypt(data, opts={})
      salt = generate_salt
      setup_cipher(:encrypt, salt)
      e = cipher.update(data) + cipher.final
      e = "Salted__#{salt}#{e}" #OpenSSL compatible
      if opts[:binary]
        e
      else
        Base64.encode64(e)
      end
    end
    alias :enc :encrypt
    alias :e :encrypt

    def decrypt(data, opts={})
      data = Base64.decode64(data)
      salt = data[8..15]
      data = data[16..-1]
      setup_cipher(:decrypt, salt)
      cipher.update(data) + cipher.final
    end
    alias :dec :decrypt
    alias :d :decrypt

    private

    def generate_salt
      s = ''
      8.times {s << rand(255).chr}
      s
    end

    def setup_cipher(method, salt)
      cipher.send(method)
      cipher.pkcs5_keyivgen(password, salt, 1)
    end
  end
end

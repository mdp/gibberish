module Gibberish
  class AES

    attr_reader :password, :size, :cipher
    def initialize(password, size=256)
      @password = password
      @size = size
      @cipher = OpenSSL::Cipher::Cipher.new("aes-#{size}-cbc")
    end

    def encrypt(data, opts={})
      @cipher.encrypt
      setup_cipher
      e = c.update(data)
      e << c.final
      e = "salted__#{@salt}#{e}" #OpenSSL compatible
      if opts[:binary]
        e
      else
        Base64.encode64(e)
      end
    end
    alias :enc, :encrypt
    alias :e, :encrypt

    def decrypt(data, opts={})
      s = data[8,8]
      data = data[16,data.length-16]
      @cipher.decrypt
      setup_cipher(s)
    end
    alias :dec, :decrypt
    alias :d, :decrypt

    private

    def setup_cipher(salt = nil)
      rounds = (size/128.0).ceil + 1
      md5_hash = []
      unless salt
        salt = ''
        8.times {salt += rand(255).chr}
      end
      ps = password + salt
      result = md5_hash[0] = Gibberish::MD5(ps, :binary => true)
      1.upto(rounds) do |i|
        md5_hash[i] = Gibberish::MD5(md5_hash[i-1] + ps, :binary => true)
        result = result + md5_hash[i]
      end
      @cipher.key = result[0, (size/8)]
      @cipher.iv = result[(size/8), 16]
      @salt = salt
    end
  end
end

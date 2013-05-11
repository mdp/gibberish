module Gibberish
  #   Handles AES encryption and decryption in a way that is compatible
  #   with OpenSSL.
  #
  #   Defaults to 256-bit CBC encryption, ideally you should leave it
  #   this way
  #
  # ## Basic Usage
  #
  # ### Encrypting
  #
  #     cipher = Gibberish::AES.new('p4ssw0rd')
  #     cipher.encrypt("some secret text")
  #     #=> "U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n"
  #
  # ### Decrypting
  #
  #     cipher = Gibberish::AES.new('p4ssw0rd')
  #     cipher.decrypt(""U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n"")
  #     #=> "some secret text"
  #
  # ## OpenSSL Interop
  #
  #     echo "U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n" | openssl enc -d -aes-256-cbc -a -k p4ssw0rd
  #
  class AES

    BUFFER_SIZE = 4096

    attr_reader :password, :size, :cipher

    # Initialize with the password
    #
    # @param [String] password
    # @param [Integer] size
    # @param [String] mode
    def initialize(password, size=256, mode="cbc")
      @password = password
      @size = size
      @mode = mode
      @cipher = OpenSSL::Cipher::Cipher.new("aes-#{size}-#{mode}")
    end

    def encrypt(data, opts={})
      salt = generate_salt(opts[:salt])
      setup_cipher(:encrypt, salt)
      e = cipher.update(data) + cipher.final
      e = "Salted__#{salt}#{e}" #OpenSSL compatible
      opts[:binary] ? e : Base64.encode64(e)
    end
    alias :enc :encrypt
    alias :e :encrypt

    def decrypt(data, opts={})
      data = Base64.decode64(data) unless opts[:binary]
      salt = data[8..15]
      data = data[16..-1]
      setup_cipher(:decrypt, salt)
      cipher.update(data) + cipher.final
    end
    alias :dec :decrypt
    alias :d :decrypt

    def encrypt_stream(in_stream, out_stream, opts={})
      salt = generate_salt(opts[:salt])
      setup_cipher(:encrypt, salt)
      out_stream << "Salted__#{salt}"
      copy_stream in_stream, out_stream
    end

    def decrypt_stream(in_stream, out_stream)
      header = in_stream.read(16)
      salt = header[8..15]
      setup_cipher(:decrypt, salt)
      copy_stream in_stream, out_stream
    end

    private

    def generate_salt(supplied_salt)
      if supplied_salt
        return supplied_salt.to_s[0,8].ljust(8,'.')
      end
      s = ''
      8.times {s << rand(255).chr}
      s
    end

    def setup_cipher(method, salt)
      cipher.send(method)
      cipher.pkcs5_keyivgen(password, salt, 1)
    end

    def copy_stream(in_stream, out_stream)
      buf = ''
      while in_stream.read(BUFFER_SIZE, buf)
        out_stream << cipher.update(buf)
      end
      out_stream << cipher.final
      out_stream.flush
    end

  end
end

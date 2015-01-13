require 'json'

module Gibberish
  # # Handles AES encryption and decryption with some sensible defaults
  #   - 256 bit AES encryption
  #   - GCM mode with Authentication
  #   - 100,000 iterations of PBKDF2_HMAC for key strengthening
  #
  # ## Compatibility with SJCL, BouncyCastle
  #   It outputs into a format that is compatible with SJCL and easy to
  #   consume in other libraries.
  #   
  #   TODO: Include BouncyCastle example
  #
  # ## Basic Usage
  #
  # ### Encrypting
  #
  #     cipher = Gibberish::AES.new('p4ssw0rd')
  #     cipher.encrypt("some secret text")
  #     #=> Outputs a string of JSON container everything that needs to be saved
  #
  # ### Decrypting
  #
  #     cipher = Gibberish::AES.new('p4ssw0rd')
  #     cipher.decrypt('{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}')
  #     #=> "some secret text"
  #
  # ## Backward compatibility with older pre 2.0 Gibberish
  #
  #  Gibberish was previously designed to be compatible with OpenSSL on the command line with CBC mode AES.
  #  This has been deprecated in favor of GCM mode, along with key hardening. However, if you pass Gibberish a
  #  string previously created with Gibberish < 2.0 or OpenSSL on the command line, it will still decrypt it.
  # 
  # ### Older AES-256-CBC mode
  # If you still want to use it, you will need to call OpenSSLCompatAES
  #
  #     cipher = Gibberish::OpenSSLCompatAES.new('p4ssw0rd')
  #     cipher.encrypt("some secret text")
  #
  #     echo "U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n" | openssl enc -d -aes-256-cbc -a -k p4ssw0rd
  #
  class AES
    def initialize(password)
      @password = password
    end

    def encrypt(data, opts={})
      SJCL.encrypt(@password, data, opts)
    end

    def decrypt(crypt, legacy_decryption=false)
      # Allow for backwards compatibility, however
      # this would also introduce non-authenticated decryption,
      # therefore it should be used with caution
      if legacy_decryption && crypt.index("U2F") == 0
        OpenSSLCompatAES.new(@password)
        return cipher.dec(crypt)
      end
      SJCL.decrypt(@password, crypt)
    end

  end
  class SJCL
    DEFAULTS = {
      v:1, iter:100_000, ks:256, ts:64,
      mode:"gcm", adata:"", cipher:"aes"
    }
    def self.encrypt(passcode, plaintext, opts={})
      opts = DEFAULTS.merge(opts)
      salt = SecureRandom.random_bytes(8)
      iv = SecureRandom.random_bytes(12)
      key = OpenSSL::PKCS5.pbkdf2_hmac(passcode, salt, opts[:iter], opts[:ks]/8, 'SHA256')
      cipherMode = "#{opts[:cipher]}-#{opts[:ks]}-#{opts[:mode]}"
      c = OpenSSL::Cipher.new(cipherMode)
      c.encrypt
      c.key = key
      c.iv = iv
      c.auth_data = opts[:adata] || ""
      ct = c.update(plaintext) + c.final
      tag = c.auth_tag(opts[:ts]);
      ct = ct + auth_tag
      out = {
        v: opts[:v], adata: opts[:adata], ks: opts[:ks], ct: Base64.strict_encode64(ct), ts: tag.length,
        iter: opts[:iter], iv:  Base64.strict_encode64(iv), salt: Base64.strict_encode64(salt)
      }
      out.to_json
    end
    def self.decrypt(passcode, h)
      begin
        h = JSON.parse(h, {:symbolize_names => true})
      rescue
        raise "Unable to parse JSON of crypted text"
      end
      key = OpenSSL::PKCS5.pbkdf2_hmac(passcode, Base64.decode64(h[:salt]), h[:iter], h[:ks]/8, 'SHA256')
      iv = Base64.decode64(h[:iv])
      ct = Base64.decode64(h[:ct])
      tag = ct[ct.length-h[:ts]/8,ct.length]
      ct = ct[0,ct.length-h[:ts]/8]
      cipherMode = "#{h[:cipher]}-#{h[:ks]}-#{h[:mode]}"
      begin
        c = OpenSSL::Cipher.new(cipherMode)
      rescue
        raise "Unsupported Cipher Mode - #{cipherMode} - Check your version of OpenSSL"
      end
      c.decrypt
      c.key = key
      c.iv = iv
      c.auth_tag = tag;
      c.auth_data = h[:adata] || ""
      c.update(ct) + c.final()
    end
  end
  class OpenSSLCompatAES

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
      raise ArgumentError, 'Data is too short' unless data.length >= 16
      data = Base64.decode64(data) unless opts[:binary]
      salt = data[8..15]
      data = data[16..-1]
      setup_cipher(:decrypt, salt)
      cipher.update(data) + cipher.final
    end
    alias :dec :decrypt
    alias :d :decrypt

    def encrypt_file(from_file, to_file, opts={})
      salt = generate_salt(opts[:salt])
      setup_cipher(:encrypt, salt)
      buf = ""
      File.open(to_file, "wb") do |outf|
        outf << "Salted__#{salt}"
        File.open(from_file, "rb") do |inf|
          while inf.read(4096, buf)
            outf << self.cipher.update(buf)
          end
          outf << self.cipher.final
        end
      end
    end
    alias :enc_file :encrypt_file
    alias :ef :encrypt_file

    def decrypt_file(from_file, to_file)
      buf = ""
      salt = ""
      File.open(to_file, "wb") do |outf|
        File.open(from_file, "rb") do |inf|
          inf.seek(8, IO::SEEK_SET)
          inf.read(8, salt)
          setup_cipher(:decrypt, salt)
          while inf.read(4096, buf)
            outf << self.cipher.update(buf)
          end
          outf << self.cipher.final
        end
      end
    end
    alias :dec_file :decrypt_file
    alias :df :decrypt_file

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

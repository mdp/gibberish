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
  #     #=> Outputs a JSON string containing everything that needs to be saved
  #
  # ### Decrypting
  #
  #     cipher = Gibberish::AES.new('p4ssw0rd')
  #     cipher.decrypt('{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}')
  #     #=> "some secret text"
  #
  #
  # ## Interoperability with SJCL's GCM mode AES
  #
  # ### Decryption with SJCL
  #
  # No special settings are required. Gibberish AES is designed to be fully compatible with SJCL
  #
  # ```javascript
  # var cleartext = sjcl.decrypt('key', 'output from Gibberish AES');
  # ```
  #
  # ### Encryption with SJCL for Gibberish
  #
  # Ruby's bindings with OpenSSL don't allow for initialization vectors of more than 3 words(12 bytes),
  # therefore you must explicitly set the IV to 12 bytes when encrypting with SJCL.
  #
  # ```javascript
  # var ciphertext = sjcl.encrypt('key', 'plain text', {mode: 'gcm', iv: sjcl.random.randomWords(3, 0)});
  # ```
  #
  # ## Backward compatibility with older pre 2.0 Gibberish
  #
  #  Gibberish was previously designed to be compatible with OpenSSL on the command line with CBC mode AES.
  #  This has been deprecated in favor of GCM mode, along with key hardening. However, you may still
  #  decrypt and encrypt using legacy convienience methods below:
  #
  # ### Legacy AES-256-CBC mode
  #
  #     cipher = Gibberish::AES::LegacyOpenSSL.new('p4ssw0rd')
  #     cipher_text = cipher.encrypt("some secret text")
  #     # => U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=
  #
  #     cipher.decrypt(cipher_text)
  #
  #     # From the command line
  #     echo "U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n" | openssl enc -d -aes-256-cbc -a -k p4ssw0rd
  #
  class AES

    # Returns the AES object
    #
    # @param [String] password
    # @param [Hash] opts
    # @option opts [Symbol] :mode ('gcm') the AES mode to use
    # @option opts [Symbol] :ks (256) keystrength
    # @option opts [Symbol] :iter (100_000) number of PBKDF2 iterations to run on the password
    # @option opts [Symbol] :max_iter (100_000) maximum allow iterations, set to prevent DOS attack of someone setting a large 'iter' value in the ciphertext JSON
    # @option opts [Symbol] :ts (64) length of the authentication data hash
    def initialize(password, opts={})
      @cipher = SJCL.new(password, opts)
    end

    # Returns the ciphertext in the form of a JSON string
    #
    # @param [String] data
    # @param [String] authenticated_data (Won't be encrypted)
    def encrypt(data, authenticated_data='')
      @cipher.encrypt(data, authenticated_data)
    end

    # Returns a plaintext string
    #
    # @param [String] ciphertext
    def decrypt(ciphertext, opts={})
      # Allow for backwards compatibility, however
      # this would also introduce non-authenticated decryption,
      # therefore it should be used with caution
      if opts[:legacy_decryption] && ciphertext.index("U2F") == 0
        LegacyOpenSSL.new(@password)
        return cipher.dec(ciphertext)
      end
      @cipher.decrypt(ciphertext)
    end

  end

  class AES::SJCL
    class CipherOptionsError < ArgumentError; end
    class DecryptionError < StandardError; end
    MAX_ITER = 100_000
    ALLOWED_MODES = ['ccm', 'gcm']
    ALLOWED_KS = [128, 192, 256]
    ALLOWED_TS = [64, 96, 128]
    DEFAULTS = {
      v:1, iter:100_000, ks:256, ts:96,
      mode:"gcm", adata:"", cipher:"aes", max_iter: MAX_ITER
    }
    def initialize(password, opts={})
      @password = password
      @opts = DEFAULTS.merge(opts)
      check_cipher_options(@opts)
    end

    def encrypt(plaintext, adata='')
      salt = SecureRandom.random_bytes(8)
      iv = SecureRandom.random_bytes(12)
      key = OpenSSL::PKCS5.pbkdf2_hmac(@password, salt, @opts[:iter], @opts[:ks]/8, 'SHA256')
      cipherMode = "#{@opts[:cipher]}-#{@opts[:ks]}-#{@opts[:mode]}"
      c = OpenSSL::Cipher.new(cipherMode)
      c.encrypt
      c.key = key
      c.iv = iv
      c.auth_data = adata
      ct = c.update(plaintext) + c.final
      tag = c.auth_tag(@opts[:ts]/8);
      ct = ct + tag
      out = {
        v: @opts[:v], adata: adata, ks: @opts[:ks], ct: Base64.strict_encode64(ct).encode('utf-8'), ts: tag.length * 8,
        mode: @opts[:mode], cipher: 'aes', iter: @opts[:iter], iv:  Base64.strict_encode64(iv),
        salt: Base64.strict_encode64(salt)
      }
      out.to_json
    end
    def decrypt(h)
      begin
        h = JSON.parse(h, {:symbolize_names => true})
      rescue
        raise "Unable to parse JSON of crypted text"
      end
      check_cipher_options(h)
      key = OpenSSL::PKCS5.pbkdf2_hmac(@password, Base64.decode64(h[:salt]), h[:iter], h[:ks]/8, 'SHA256')
      iv = Base64.decode64(h[:iv])
      ct = Base64.decode64(h[:ct])
      tag = ct[ct.length-h[:ts]/8,ct.length]
      ct = ct[0,ct.length-h[:ts]/8]
      cipherMode = "#{h[:cipher]}-#{h[:ks]}-#{h[:mode]}"
      begin
        c = OpenSSL::Cipher.new(cipherMode)
      rescue RuntimeError => e
        raise "OpenSSL error when initializing: #{e.message}"
      end
      c.decrypt
      c.key = key
      c.iv = iv
      c.auth_tag = tag;
      c.auth_data = h[:adata] || ""
      begin
        out = c.update(ct) + c.final();
      rescue OpenSSL::Cipher::CipherError => e
        raise DecryptionError.new();
      end
      return out.force_encoding('utf-8')
    end

    # Assume the worst
    def check_cipher_options(c_opts)
      if @opts[:max_iter] < c_opts[:iter]
        # Prevent DOS attacks from high PBKDF iterations
        # You an increase this by passing in opts[:max_iter]
        raise CipherOptionsError.new("Iteration count of #{c_opts[:iter]} exceeds the maximum of #{@opts[:max_iter]}")
      elsif !ALLOWED_MODES.include?(c_opts[:mode])
        raise CipherOptionsError.new("Mode '#{c_opts[:mode]}' not supported")
      elsif !ALLOWED_KS.include?(c_opts[:ks])
        raise CipherOptionsError.new("Keystrength of #{c_opts[:ks]} not supported")
      elsif !ALLOWED_TS.include?(c_opts[:ts])
        raise CipherOptionsError.new("Tag length of #{c_opts[:ts]} not supported")
      elsif c_opts[:iv] && Base64.decode64(c_opts[:iv]).length > 12
        raise CipherOptionsError.new("Initialization vector's greater than 12 bytes are not supported in Ruby.")
      end
    end
  end

  class AES::LegacyOpenSSL

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

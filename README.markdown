# Gibberish - Encryption in Ruby made simple
![Travis](https://secure.travis-ci.org/mdp/gibberish.png)

### Goals
- This library should remain easily iteroperable with other libraries
- It should default to a reasonably secure setting, e.g. 256-bit AES, or SHA1 for HMAC
But it should allow the user to specify a stronger setting, within reason.
- Targets more recent versions of Ruby(>=2.0) with better OpenSSL support


## Requirements

Ruby 2.0 or later, compiled with OpenSSL support

## Installation

    gem install gibberish

## AES

AES encryption with sensible defaults:

- 100,000 iterations of PBKDF2 password hardening
- GCM mode with authentication
- Ability to include authenticated data
- Compatible with SJCL, meaning all ciphertext is decryptable in JS via SJCL

### Encrypting

    cipher = Gibberish::AES.new('p4ssw0rd')
    cipher.encrypt("some secret text")
    #=> Outputs a string of JSON container everything that needs to be saved

### Decrypting

    cipher = Gibberish::AES.new('p4ssw0rd')
    cipher.decrypt('{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}')
    #=> "some secret text"

#### Previous versions and OpenSSL

Gibberish <2.0 was designed to be compatible with OpenSSL on the command line. While this is no longer the case, ciphertext from 
versions prior to 2.0 can be decoded using the following compatibility layer.

    cipher = Gibberish::OpenSSLCompatAES.new('p4ssw0rd')
    cipher.decrypt("U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=")

## RSA

    k = Gibberish::RSA.generate_keypair(1024)
    cipher = Gibberish::RSA.new(k.public_key)
    enc = cipher.encrypt("Some data")
    # Defaults to Base64 output
    #=> "JKm98wKyJljqmpx7kP8ZsdeXiShllEMcRHVnjUjc4ecyYK/doKAkVTLho1Gp\ng697qrljyClF0AcIH+XZmeF/TrqYUuCEUyhOD6OL1bs5dn8vFQefS5KdaC5Y\ndLADvh3mSfE/w/gs4vaf/OtbZNBeSl6ROCZasWTfRewp4n1RDmE=\n"
    cipher = Gibberish::RSA.new(k.private_key)
    dec = cipher.decrypt(enc)

[Find out more](http://mdp.github.com/gibberish/Gibberish/RSA.html)

## HMAC

Defaults to SHA256

    Gibberish::HMAC("key", "some data")
    #=> 521677c580722c5c52fa15d978e8656341c4f3c5

Other digests can be used

    Gibberish::HMAC("key", "some data", :digest => :sha1)
    #=> 01add3f98ce4d49403d98362a046c6cca2c79d778426282c53e4f628f648c12b

[Find out more](http://mdp.github.com/gibberish/Gibberish/HMAC.html)

## Digests

    Gibberish::MD5("somedata")
    #=> aefaf7502d52994c3b01957636a3cdd2

    Gibberish::SHA1("somedata")
    #=> efaa311ae448a7374c122061bfed952d940e9e37

    Gibberish::SHA224("somedata")
    #=> a39b86d838273f5ff4879c26f85e3cb333bb44d73b24f275bad1a6c6

    Gibberish::SHA256("somedata")
    #=> 87d149cb424c0387656f211d2589fb5b1e16229921309e98588419ccca8a7362

    Gibberish::SHA384("somedata")
    #=> b6800736973cc061e3efb66a34f8bda8fa946804c6cc4f26a6b9b3950211078801709d0d82707c569a07c8f63c804c87

    Gibberish::SHA512("somedata")
    #=> a053441b6de662599ecb14c580d6637dcb856a66b2a40a952d39df772e47e98ea22f9e105b31463c5cf2472feae7649464fe89d99ceb6b0bc398a6926926f416

[Find out more](http://mdp.github.com/gibberish/Gibberish/Digest.html)

## Run the tests

    git clone https://github.com/mdp/gibberish.git
    cd gibberish
    bundle install
    rake test

## TODO

- Cover OpenSSL exceptions with more reasonable and easier to understand exceptions.

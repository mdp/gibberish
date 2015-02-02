#### NOTICE: Breaking Changes in 2.0

Checkout the [Changelog](CHANGELOG.mdown) for a full list of changes in 2.0

# Gibberish - A ruby encryption library
![Travis](https://secure.travis-ci.org/mdp/gibberish.png)

### Goals
- AES encryption should have sensible defaults
- AES should be interoperable with SJCL for browser based decryption/encryption
- Simple API for HMAC/Digests
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
    #=> Outputs a string of JSON containing everything that needs to be saved for future decryption
    # Example: '{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}'

### Decrypting

    cipher = Gibberish::AES.new('p4ssw0rd')
    cipher.decrypt('{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}')
    #=> "some secret text"

### Interoperability with SJCL (JavaScript - Browser/Node.js)

AES ciphertext from Gibberish is compatible with [SJCL](http://bitwiseshiftleft.github.io/sjcl/), a JavaScript library which
works in the browser and Node.js

#### Decrypting

```javascript
// In the browser
var cleartext = sjcl.decrypt('key', '[output from Gibberish AES]');
```

#### Encrypting

```javascript
// In the browser
// Ruby OpenSSL cannot handle an IV longer than 12 bytes, therefore we need to tell SJCL to
// only use a 3 word IV value. See: https://github.com/bitwiseshiftleft/sjcl/issues/180
var ciphertext = sjcl.encrypt('key', 'plain text', {mode: 'gcm', iv: sjcl.random.randomWords(3, 0)});
```

### Previous versions and OpenSSL

Gibberish <2.0 was designed to be compatible with OpenSSL on the command line. While this is no longer the case, ciphertext from
versions prior to 2.0 can be decoded using the following compatibility layer.

    cipher = Gibberish::OpenSSLCompatAES.new('p4ssw0rd')
    cipher.decrypt("U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=")

[See the full docs](http://www.rubydoc.info/github/mdp/gibberish/Gibberish/AES)

## HMAC

    Gibberish::HMAC256("password", "data")
    # => "cccf6f0334130a7010d62332c75b53e7d8cea715e52692b06e9cd41b05644be3"

Other digests are available

    Gibberish::HMAC512("password", "data") # SHA512
    # => "abf85192282b501874f4803ea08672f2c9d6e656c57801023a0b1f4dd9492ba960efdb560a8618ec783327d6dc31577422651a4cf7eaf722d2caefbc04038c6e"

    # or
    Gibberish::HMAC("password", "data", :sha512)

[See the full docs](http://www.rubydoc.info/github/mdp/gibberish/Gibberish/HMAC)

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

[See the full docs](http://www.rubydoc.info/github/mdp/gibberish/Gibberish/Digest)

## Run the tests

    git clone https://github.com/mdp/gibberish.git
    cd gibberish
    make

## TODO


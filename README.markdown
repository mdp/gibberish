# Gibberish
### Stop looking up encryption code snippets!

## Digests

    Gibberish::MD5("somedata")
    #=> aefaf7502d52994c3b01957636a3cdd2

    Gibberish::SHA1("somedata")
    #=> efaa311ae448a7374c122061bfed952d940e9e37

    Gibberish::SHA256("somedata")
    #=> 87d149cb424c0387656f211d2589fb5b1e16229921309e98588419ccca8a7362

## AES

    cipher = Gibberish::AES.new("p4ssw0rd")
    cipher.enc("Some top secret data")
    #=> U2FsdGVkX187oKRbgDkUcMKaFfB5RsXQj/X4mc8X3lsUVgwb4+S55LQo6f6N\nIDMX

    cipher.dec("U2FsdGVkX187oKRbgDkUcMKaFfB5RsXQj/X4mc8X3lsUVgwb4+S55LQo6f6N\nIDMX")
    #=> "Some top secret data"

Gibberish AES is fully compatible with default OpenSSL on the command line

    echo "U2FsdGVkX187oKRbgDkUcMKaFfB5RsXQj/X4mc8X3lsUVgwb4+S55LQo6f6N\nIDMX\n" | \
    openssl enc -d -aes-256-cbc -a -k p4ssw0rd

## HMAC

    Gibberish::HMAC("key", "some data")
    #=> 521677c580722c5c52fa15d978e8656341c4f3c5

## PKI

Coming soon

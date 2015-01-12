require 'bundler/setup'; require 'gibberish';
c = Gibberish::AES.new("s33krit");

json = '{"iv":"FnCTbf0w7xE9VK9R","v":1,"iter":1000,"ks":256,"ts":128,"mode":"gcm","adata":"","cipher":"aes","salt":"tBUqeycs1f8=","ct":"y8yCraJk9ohgR/u1TlvpOq8ldi+sGg=="}'
p c.decrypt(json);
json = '{"iv":"ErLMwHAqvOQfxaiS","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"mgxZybSxOSV0s9uxrcKgE5+qu0BmQ11Kz2rdpk1BIush6WCr0EPpDTOfe6lxtMkl56XRmcue2gs="}'
p c.decrypt(json);
json = '{"iv":"saWaknqlf5aalGyU","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"nKsmfrNBh39Rcv9KcMkIAl3sSapmou8A"}'
p c.decrypt(json);
# Long IV
json = '{"iv":"E51tGDbuXpPEqkZJdJ5oGg==","v":1,"iter":1000,"ks":256,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"0GXgxJ/QAUo=","ct":"2IIRvLFBB82HjAL2kvVKlQ=="}'
p c.decrypt(json);

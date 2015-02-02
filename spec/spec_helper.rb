require 'rubygems'
require 'bundler/setup'
gem 'minitest' # ensures you're using the gem, and not the built in MT
require 'minitest/autorun'

require 'gibberish'

print "Ruby version #{RUBY_VERSION} - OpenSSL version: #{OpenSSL::OPENSSL_VERSION}\n"

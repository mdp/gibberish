all: install test docs

install:
	bundle install;

test:
	bundle exec rake;

benchmark:
	ruby spec/*_benchmark.rb;

docs:
	rm -rf doc;
	bundle exec yard;

.PHONY: install test docs benchmark

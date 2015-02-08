all: install test docs

install:
	bundle install;

test:
	bundle exec rake;

docs:
	rm -rf doc;
	bundle exec yard;

.PHONY: install test docs

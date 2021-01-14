.PHONY: all
all: test

.PHONY: test
test:
	@scripts/check_unit.sh


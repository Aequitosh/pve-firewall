TESTS = test_parse_address_list

.PHONY: all test $(TESTS) clean
all: test

test: $(TESTS)

$(TESTS): %: %.pl
	./$<

clean:

TESTS = test_parse_address_list test_ipt_rule_to_cmds test_parameter_newlines test_compile_ipsets test_simulator_protocols test_interface_names

.PHONY: all test $(TESTS) clean
all: test

test: $(TESTS)

$(TESTS): %: %.pl
	./$<

clean:

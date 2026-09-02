#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::FirewallSimulator;

my @protocols =
    (['tcp', 6], ['udp', 17], ['icmp', 1], ['igmp', 2], ['icmpv6', 58], ['udplite', 136]);

for my $rule_protocol (@protocols) {
    for my $packet_protocol (@protocols) {
        for my $rule_name (@$rule_protocol) {
            for my $packet_name (@$packet_protocol) {
                my @result = eval {
                    PVE::FirewallSimulator::rule_match(
                        {},
                        'TEST',
                        "-A TEST -p $rule_name -j ACCEPT",
                        { proto => $packet_name },
                    );
                };
                is($@, '', "$rule_name rule and $packet_name packet parse");
                my $expected =
                    $rule_protocol->[1] == $packet_protocol->[1] ? [0, 'ACCEPT'] : [undef];
                is_deeply(\@result, $expected, "$rule_name rule and $packet_name packet match");
            }
        }
    }
}

done_testing();

#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

my $valid_inputs = {
    "192.0.2.0" => 4,
    "192.0.2.001" => 4,
    "192.0.2.077" => 4,
    "192.000.002.000/24" => 4,
    "192.0.2" => 4,
    "192.0" => 4,
    "192" => 4,
    "192/32" => 4,
    "0/0" => 4,
    "0.0.0.0/0" => 4,
    "0.0.0.0/0.0.0.0" => 4,
    "192/12" => 4,
    "192.0.2.0/24" => 4,
    "192.0.2.0/32" => 4,
    "192.0.2.0/255.255.255.0" => 4,
    "192.0.2.0/255.255.0.0" => 4,
    "192.0.2.0/253.0.0.0" => 4,
    "192.0.2.1/255.0.255.255" => 4,
    "192.0.2.0/255.255.255.000" => 4,
    "192.0.2.0/255.255.255.077" => 4,
    "192.0.2.0/0255.255.255.0" => 4,
    "192.0.2.0,192.0.2.2/31" => 4,
    "fe80::" => 6,
    "fe80::1" => 6,
    "fe80::1/ff80::" => 6,
    "fe80::1/128" => 6,
    "fe80:fff:123::1/128" => 6,
    "::/::" => 6,
    "::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:0" => 6,
    "::/::ffff:255.255.255.0" => 6,
    "fe80::1/ffff:0:ffff::" => 6,
    "fe80::1/FFFF:0:FFFF::" => 6,
    "fe80::1-fe80::2" => 6,
    "fe80::1,fe80::2/128" => 6,
    "+ipset" => undef,
    "+dc/ipset_qwe-zxc" => undef,
    "+guest/ipset_qwe-zxc" => undef,
    "alias" => undef,
    "dc/alias" => undef,
    "guest/alias" => undef,
    "q--_-____---qwe78878AAAA" => undef,
    "+q--_-____---qwe78878AAAA" => undef,
    "192.0.2.0-192.0.2.1" => 4,
};

for my $input (sort keys $valid_inputs->%*) {
    my $expected_ipversion = $valid_inputs->{$input};
    my $ipversion = eval { PVE::Firewall::parse_address_list($input) };

    is($@, '', "no error: $input");
    is($ipversion, $expected_ipversion, "valid: $input");
}

my @invalid_inputs = (
    "256.0.0.0",
    "256.0.0.0.0",
    "192.0.2.0-192.0.2.0/31",
    "192.0.2.0/33",
    "192.0.2.0/99",
    "192.0.2.0/0",
    "192/0",
    "192.0.2.1/24",
    "fe80::1/0",
    "192.0.2.0-fe80::1",
    "fe80::1-192.0.2.0",
    "192.0.2.1-192.0.2.0",
    "192.0.2.0-192.0.2.10,192.0.2.20",
    "invalid_chars_in_alias_name:",
    "guest/invalid_chars_in_alias_name:",
);

for my $input (@invalid_inputs) {
    eval { PVE::Firewall::parse_address_list($input) };
    ok($@, "invalid: $input");
}

done_testing();

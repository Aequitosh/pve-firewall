#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

for my $cidr ('192.0.2.0/99', '2001:db8::/129') {
    eval { PVE::Firewall::parse_ip_or_cidr($cidr) };
    ok($@, "reject invalid CIDR $cidr");
}

subtest 'container IP filters' => sub {
    plan skip_all => 'PVE::LXC::Config is not installed'
        if !eval { require PVE::LXC::Config; 1 };

    PVE::Firewall::set_verbose(1);
    PVE::Firewall::local_network('192.0.2.0/24');

    for my $ip (undef, 'dhcp', 'manual', '192.0.2.10/24') {
        for my $ip6 (undef, 'auto', 'dhcp', 'manual', '2001:db8::10/64') {
            my $network = 'name=eth0,hwaddr=02:00:00:00:00:01,bridge=vmbr0,firewall=1';
            $network .= ",ip=$ip" if defined($ip);
            $network .= ",ip6=$ip6" if defined($ip6);
            my $label = 'ip=' . ($ip // '<unset>') . ',ip6=' . ($ip6 // '<unset>');
            my $cluster = { aliases => {}, ipset => {}, sdn => { ipset => {} } };
            my $configs = { 100 => { vmid => 100, options => { ipfilter => 1 }, ipset => {} } };
            my $vmdata = { qemu => {}, lxc => { 100 => { net0 => $network } } };
            my @warnings;
            local $SIG{__WARN__} = sub { push @warnings, @_ };

            my $sets = PVE::Firewall::compile_ipsets($cluster, $configs, $vmdata);
            is_deeply(\@warnings, [], "$label compiles without errors");

            for my $version (4, 6) {
                my $name = "PVEFW-100-ipfilter-net0-v$version";
                ok(exists($sets->{$name}), "$label creates IPv$version set");
                my @entries = grep { /^add / } @{ $sets->{$name} // [] };
                my @expected;
                if ($version == 4) {
                    push @expected, "add $name 192.0.2.10"
                        if defined($ip) && $ip eq '192.0.2.10/24';
                } else {
                    push @expected, "add $name 2001:db8::10"
                        if defined($ip6) && $ip6 eq '2001:db8::10/64';
                    push @expected, "add $name fe80::/10 nomatch", "add $name fe80::ff:fe00:1";
                }
                is_deeply(\@entries, \@expected, "$label IPv$version filter addresses");
            }
        }
    }
};

done_testing();

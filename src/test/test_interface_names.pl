#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use File::Temp qw(tempdir);
use Test::More;

use PVE::Firewall;
use PVE::Network;

PVE::Firewall::set_verbose(1);
PVE::Firewall::local_network('192.0.2.0/24');

sub cluster_config {
    return {
        options => { enable => 1 },
        rules => [],
        groups => {},
        ipset => {},
        aliases => { local_network => { cidr => '192.0.2.0/24', ipversion => 4 } },
        sdn => { ipset => {} },
    };
}

subtest 'host and cluster alternative names' => sub {
    my $altname = 'enx00112233445566';
    my $mapping =
        PVE::Network::altname_mapping({ eno1 => { ifname => 'eno1', altnames => [$altname] } });
    is($mapping->{$altname}, 'eno1', 'alternative name maps to short kernel name');
    no warnings 'redefine';
    local *PVE::Network::altname_mapping = sub { return $mapping };

    for my $env ('host', 'cluster') {
        for my $direction ('in', 'out') {
            for my $type ($direction, 'group') {
                for my $iface ($altname, 'e' x 15, 'e' x 16) {
                    my $cluster = cluster_config();
                    $cluster->{groups}->{example} = [];
                    my $action = $type eq 'group' ? 'example' : 'DROP';
                    my $line = uc($type) . " $action -i $iface";
                    my $rule = PVE::Firewall::parse_fw_rule('test', $line, $cluster, {}, $env);
                    ok(!$rule->{errors}, "$env: accept selector $line");
                    my $host = { options => {}, rules => [] };
                    push @{ ($env eq 'host' ? $host : $cluster)->{rules} }, $rule;
                    my $ruleset = { 'PVEFW-INPUT' => [], 'PVEFW-OUTPUT' => [] };
                    my @warnings;
                    local $SIG{__WARN__} = sub { push @warnings, @_ };
                    PVE::Firewall::enable_host_firewall($ruleset, $host, $cluster, 4, undef);
                    my $resolved = $mapping->{$iface} // $iface;
                    my $flag = $direction eq 'in' ? '-i' : '-o';
                    my $chain = $ruleset->{ 'PVEFW-HOST-' . uc($direction) };
                    my @matches = grep { /\Q$flag $resolved\E / } @$chain;
                    is(
                        scalar(@matches),
                        length($resolved) > 15 ? 0 : 1,
                        "$env/$direction/$type: match resolved name $resolved",
                    );

                    if (length($resolved) > 15) {
                        like(join('', @warnings), qr/\Q$resolved\E/,
                            'log rejected kernel name');
                    } else {
                        is_deeply(\@warnings, [], 'valid kernel name does not warn');
                    }
                }
            }
        }
    }
};

subtest 'invalid container interface does not remove valid interfaces' => sub {
    plan skip_all => 'PVE::LXC::Config is not installed'
        if !eval { require PVE::LXC::Config; 1 };
    my $directory = tempdir('test-interface-names-XXXXXX', DIR => '.', CLEANUP => 1);
    PVE::Tools::file_set_contents("$directory/cluster.fw", "[OPTIONS]\nenable: 1\n");
    PVE::Tools::file_set_contents("$directory/999999999.fw", "[OPTIONS]\nenable: 1\n");
    no warnings 'redefine';
    local *PVE::Firewall::load_sdn_conf = sub { return { ipset => {}, ipset_comments => {} } };
    my $vmdata = {
        testdir => $directory,
        qemu => {},
        lxc => {
            999999999 => {
                net0 => 'name=eth0,hwaddr=02:00:00:00:00:01,bridge=vmbr0,firewall=1',
                net2 => 'name=eth2,hwaddr=02:00:00:00:00:02,bridge=vmbr0,firewall=1',
            },
        },
    };
    my ($before) = PVE::Firewall::compile(undef, undef, $vmdata, {});
    $vmdata->{lxc}->{999999999}->{net10} =
        'name=eth10,hwaddr=02:00:00:00:00:0a,bridge=vmbr0,firewall=1';
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    my ($v4, undef, $v6, $eb) = PVE::Firewall::compile(undef, undef, $vmdata, {});
    like(join('', @warnings), qr/veth999999999i10/, 'log overlong guest interface');

    for my $pair (['IPv4', $v4->{filter}], ['IPv6', $v6->{filter}], ['ebtables', $eb]) {
        my ($name, $ruleset) = @$pair;
        ok(exists($ruleset->{'veth999999999i0-OUT'}), "$name retains net0");
        ok(!exists($ruleset->{'veth999999999i10-OUT'}), "$name skips overlong net10");
        ok(exists($ruleset->{'veth999999999i2-OUT'}), "$name retains net2 after net10");
    }

    my $active = {
        map { $_ => PVE::Firewall::iptables_chain_digest($before->{filter}->{$_}) }
            keys %{ $before->{filter} }
    };
    local *PVE::Firewall::iptables_get_chains =
        sub { return ($active, { INPUT => 1, OUTPUT => 1, FORWARD => 1 }) };
    my $commands = PVE::Firewall::get_ruleset_cmdlist($v4->{filter});
    unlike(
        $commands,
        qr/^-X veth999999999i[02]-(?:IN|OUT)$/m,
        'do not delete valid active chains',
    );
};

done_testing();

#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

for my $ipversion (4, 6) {
    for my $proto ('udplite', '136') {
        for my $sport (undef, '0', '1234', '1234:1236', '1234,1236') {
            for my $dport (undef, '0', '4321', '4321:4323', '4321,4323') {
                my $line = "IN ACCEPT -p $proto";
                $line .= " -sport $sport" if defined($sport);
                $line .= " -dport $dport" if defined($dport);

                my $rule = PVE::Firewall::parse_fw_rule('test', $line, {}, {}, 'host');
                ok(!$rule->{errors}, "IPv$ipversion: validate $line");

                my $expected = "-A TEST -p $proto";
                $expected .= " --match multiport --dports $dport" if defined($dport);
                $expected .= " --match multiport --sports $sport" if defined($sport);
                $expected .= ' -j ACCEPT';

                is_deeply(
                    [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $ipversion, {}, {})],
                    [$expected],
                    "IPv$ipversion: compile $line",
                );
            }
        }
    }

    for my $proto ('tcp', '6', 'udp', '17') {
        my $rule = { proto => $proto, sport => '1234', dport => '4321', action => 'ACCEPT' };
        is_deeply(
            [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $ipversion, {}, {})],
            ["-A TEST -p $proto --sport 1234 --dport 4321 -j ACCEPT"],
            "IPv$ipversion: $proto single ports do not need multiport",
        );
    }
}

for my $proto ('icmp', 'icmpv6') {
    my $version = $proto eq 'icmp' ? 4 : 6;
    my $type = $proto eq 'icmp' ? 'icmp-type' : 'icmpv6-type';
    my $rule = PVE::Firewall::parse_fw_rule('test', "IN ACCEPT -p $proto -dport 0", {}, {}, 'host');
    ok(!$rule->{errors}, "$proto accepts type zero");
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $version, {}, {})],
        ["-A TEST -p $proto -m $proto --$type 0 -j ACCEPT"],
        "$proto preserves type zero restriction",
    );
}

for my $proto ('tcp', 'udp', 'sctp', 'udplite', '136') {
    my $rule = { proto => $proto, sport => '0', dport => '0', action => 'ACCEPT' };
    my $ports =
        $proto eq 'udplite' || $proto eq '136'
        ? '--match multiport --dports 0 --match multiport --sports 0'
        : '--sport 0 --dport 0';
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {})],
        ["-A TEST -p $proto $ports -j ACCEPT"],
        "$proto preserves zero source and destination ports",
    );

    $rule->{sport} = 'ssh';
    $rule->{dport} = 'bootps';
    $ports =
        $proto eq 'udplite' || $proto eq '136'
        ? '--match multiport --dports 67 --match multiport --sports 22'
        : '--sport 22 --dport 67';
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {})],
        ["-A TEST -p $proto $ports -j ACCEPT"],
        "$proto resolves port aliases independently of the service protocol",
    );
}

for my $proto ('udplite', '136') {
    for my $field ('sport', 'dport') {
        for my $port ('65536', '1236:1234', '1234,') {
            my $rule = { proto => $proto, $field => $port, action => 'ACCEPT' };
            eval { PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {}) };
            ok($@, "$proto rejects invalid $field $port");
        }
    }
}

done_testing();

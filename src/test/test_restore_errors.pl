#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;
use PVE::Tools;

for my $wrapper (
    'iptables_restore_cmdlist',
    'ip6tables_restore_cmdlist',
    'ipset_restore_cmdlist',
    'ebtables_restore_cmdlist',
) {
    for my $case (
        ['', 0], ['', 7],
        ["fatal last line\n", 2],
        ["warning first line\nfatal last line\n", 2],
        ["detail first line\ndetail second line\nfatal last line\n", 2],
    ) {
        my ($stderr, $status) = @$case;
        my $fn = PVE::Firewall->can($wrapper);
        no warnings 'redefine';
        local *PVE::Firewall::run_command = sub {
            my ($command, %params) = @_;
            like(
                $command->[0],
                qr/^(?:ip6?tables-restore|ipset|ebtables-restore)\z/,
                'intercept restore command',
            );
            return PVE::Tools::run_command(
                [
                    $^X,
                    '-e',
                    'local $/; scalar(<STDIN>); print STDERR $ARGV[0]; exit $ARGV[1]',
                    $stderr,
                    $status,
                ],
                %params,
            );
        };
        my $result = eval { $fn->('test input') };
        my $error = $@;
        if (!$status) {
            is($error, '', "$wrapper success does not throw");
            is($result, 0, "$wrapper returns success status");
        } elsif ($stderr eq '') {
            like($error, qr/exit code 7/, "$wrapper retains silent exit failure");
        } else {
            for my $line (split(/\n/, $stderr)) {
                like($error, qr/\Q$line\E\n/, "$wrapper retains $line");
            }
            my $context =
                $wrapper eq 'ip6tables_restore_cmdlist' ? 'iptables_restore_cmdlist' : $wrapper;
            like($error, qr/\Q$context\E:/, "$wrapper retains command error context");
        }
    }
}

done_testing();

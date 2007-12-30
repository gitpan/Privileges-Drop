package Privileges::Drop;
use strict;
use warnings;
use English;
use Carp;

our $VERSION = '1.00';

=head1 NAME

Privileges::Drop - A module to make it simple to drop all privileges, even 
POSIX groups.

=head1 DESCRIPTION

This module tries to simplify the process of dropping privileges. This can be
useful when your Perl program needs to bind to privileged ports, etc. This
module is much like Proc::UID, except that it's implemented in pure Perl.


=head1 SYNOPSIS
  
  use Privileges::Drop;

  # Do privileged stuff

  # Drops privileges and sets euid/uid to 1000 and egid/gid to 1000.
  drop_uidgid(1000, 1000);

  # Drop privileges to user nobody looking up gid and uid with getpwname
  # This also set the enviroment variables USER, LOGNAME, HOME and SHELL. 
  drop_privileges('nobody');

=head1 METHODS

=over

=cut

use base "Exporter";

our @EXPORT = qw(drop_privileges drop_uidgid);

=item drop_uidgid($uid, $gid, @groups)

Drops privileges and sets euid/uid to $uid and egid/gid to $gid.

Supplementary groups can be set in @groups.

=cut

sub drop_uidgid {
    my ($uid, $gid, @groups) = @_;
   
    # Sort the groups and make sure they are uniq 
    my %groups = map { $_ => 1 } grep { $_ ne $gid } (@groups);
    my $newgid ="$gid ".join(" ", sort { $a <=> $b} keys %groups);
    
    # Drop privileges to $uid and $gid for both effective and save uid/gid
    $GID = $EGID = $newgid;
    $UID = $EUID = $uid;
    
    # Perl adds $gid two time to the list so it also gets set in posix groups
    $newgid ="$gid ".join(" ", sort { $a <=> $b} keys %groups, $gid);

    # Sort the output so we can compare it
    my $cgid = int($GID)." ".join(" ", sort { $a <=> $b } split(/\s/, $GID));
    my $cegid = int($EGID)." ".join(" ", sort { $a <=> $b } split(/\s/, $EGID));
    
    # Check that we did actually drop the privileges
    if($UID ne $uid or $EUID ne $uid or $cgid ne $newgid or $cgid ne $newgid) {
        croak("Could not set current uid:$UID, gid:$cgid, euid=$EUID, egid=$cegid "
            ."to uid:$uid, gid:$newgid");
    }
}

=item drop_privileges($user)

Drops privileges to the $user, looking up gid and uid with getpwname and 
calling drop_uidgid() with these arguments.

The environment variables USER, LOGNAME, HOME and SHELL are also set to the
values returned by getpwname.

Returns the $uid and $gid on success and dies on error.

NOTE: If drop_privileges() is called when you don't have root privileges
it will just return the current $uid, $gid;

=cut

sub drop_privileges {
    my ($user) = @_;

    # Check if we are root and stop if we are not.
    if($UID != 0 and $EUID != 0 and $GID =~ /0/ and $EGID =~ /0/) {
        return ($UID, $GID);
    }
    
    # Find user in passwd file
    my ($uid, $gid, $home, $shell) = (getpwnam($user))[2,3,7,8];
    if(!defined $uid or !defined $gid) {
        croak("Could not find uid and gid user:$user");
    }

    # Find all the groups the user is a member of
    my @groups;
    while (my ($name, $comment, $ggid, $mstr) = getgrent()) {
        my %membership = map { $_ => 1 } split(/\s/, $mstr);
        if(exists $membership{$user}) {
            push(@groups, $ggid) if $ggid ne 0;
        }
    }

    # Cleanup $ENV{}
    $ENV{USER} = $user;
    $ENV{LOGNAME} = $user;
    $ENV{HOME} = $home;
    $ENV{SHELL} = $shell;

    drop_uidgid($uid, $gid, @groups);

    return ($uid, $gid, @groups);
}

=back

=head1 NOTES

As this module only uses Perl's build in function, it relies on them to work
correctly. That means setting $GID and $EGID should also call setgroups(),
something that might not have been the case before Perl 5.004. So if you are 
running an older version, Proc::UID might be a better choice.

=head1 AUTHOR

Troels Liebe Bentsen <tlb@rapanden.dk> 

=head1 COPYRIGHT

Copyright(C) 2007 Troels Liebe Bentsen

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;

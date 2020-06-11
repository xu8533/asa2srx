#!/usr/bin/perl
# px2sx.pl, version 2.58, 10th July 2012, (c) Telecom NZ Ltd
# Originally created by David Hunter <david.hunter@gen-i.co.nz>
# Distributed under the Artistic License 2.0
# NetAddr::IP module is (c) Luis E. Muñoz 1999-2007 and (c) Michael Robinton 2006-2010

# This script is provided on an "as is" and "as available" basis and your use of it is at your sole risk.
# Telecom New Zealand Limited (including its subsidiaries, affiliates, employees, directors, officers, agents
# or subcontractors) expressly disclaims all warranties of any kind related to the script, either expressed
# or implied, and all liability for any loss or damage associated with use of the script.
=pod
%zonelist
%iplist
array @all save all asa configuration 
array @acl each asa configuration line
array @svcs save all services.csv 

=cut

use 5.012;
no strict;
no warnings 'experimental';
use Getopt::Std;
use Scalar::Util qw(looks_like_number);
use NetAddr::IP;
use Cwd 'abs_path';
use File::Basename;

$my_path = dirname(abs_path($0));

if ($#ARGV < 0 || $#ARGV > 5) { die "\nUsage:\tperl px2sx.pl [-cgjns] [-p <STRING>] [-z <zone.file>] <config.file>\n
Flags:\t-c Create .CSV files as well as Junos configuration
\t-g Write address objects to the global address-book
\t-j Generate config file syntax instead of set commands
\t-n Do not combine ACLs, ie: one policy per ACL
\t-s Partial ACL combining; services only
\t-p <STRING> Prepend security policies with this string
\t-z <zone.file > Do not create a Zone file, use this one instead\n\n"; }

getopts("ncz:jp:sg", \%options);
print "\nStarting conversion to Junos...\n\n";
print "Creating CSV tables...\n" if defined $options{c};
print "Making config-type output..\n" if defined $options{j};
print "NOT fixing rulebase...\n" if defined $options{n};
print "ONLY combining policies by service...\n" if defined $options{s};
print "Prepending $options{p} to policies...\n" if defined $options{p};
print "Writing address objects to global zone...\n" if defined $options{g};
print "Using existing Zone file $options{z}\nCannot match Source NATs, ARPs or ACLs to Zones...\n" if defined $options{z};
print "\n";

open(file, "< $ARGV[0]") or die "Can't open config file $ARGV[0] for read\n";
@all=<file>;
close(file);
open(zone, "> zones.txt") or die "Can't open zones.txt for write\n" if !defined $options{z};
if (defined $options{c}) {
	open(otables, "> obj-tables.csv") or die "Can't open obj-tables.csv for write\n";
	open(gtables, "> grp-tables.csv") or die "Can't open grp-tables.csv for write\n";	
	open(stables, "> svc-tables.csv") or die "Can't open svc-tables.csv for write\n";
	open(rtables, "> rule-tables.csv") or die "Can't open rule-tables.csv for write\n";
	open(ntables, "> nat-tables.csv") or die "Can't open nat-tables.csv for write\n";
	open(ttables, "> route-tables.csv") or die "Can't open route-tables.csv for write\n";
}
open(sroutes, "> routes.txt") or die "Can't open routes.txt for write\n";
open(nats, "> nats.txt") or die "Can't open nats.txt for write\n";
if (defined $options{j}) {
	print sroutes "routing-options {\n\tstatic {\n";
	print nats "security {\n\tnat {\n\t\tsource {\n";
}
$set=$rule=1;
print "Zones & Routes...\n";
foreach $line (@all) {
	@acl = split(" ", $line);
	chomp($acl[2]);
	chomp($acl[3]) if ($#acl > 2);
	given($acl[0]) {
		when ("object") {
			$objname=$acl[2] if ($acl[1] eq "network");
		}
		when ("subnet") {
			$ip=NetAddr::IP->new($acl[1],$acl[2]);
			$iplist{$objname}=$ip;
		}
		when ("host") {
			$ip=NetAddr::IP->new($acl[1],"255.255.255.255");
			$iplist{$objname}=$ip;
		}
		when ("name") {
  		$ip=NetAddr::IP->new($acl[1]);
  		$iplist{$acl[2]}=$ip;
		}
		when ("pdm") {
			if ($acl[1] eq "location" && exists $iplist{$acl[2]}) {
				$ip=NetAddr::IP->new($iplist{$acl[2]}->addr,$acl[3]);
				if ($ip->masklen ne $iplist{$acl[2]}->masklen) {
					$iplist{$acl[2]}=$ip;
					print "Using pdm for $acl[2]\n";
				}
			}
		}
		when ("nameif") {
			if ($#acl < 3) { $nameif=$acl[1]; $v8=1; }
		}
		when ("ip") {
			if ($acl[1] eq "address") {
				if (!defined $v8) { $j=3; $nameif=$acl[2]; } else { $j=2; }
				if (exists $iplist{$acl[$j]}) { $intaddress=new NetAddr::IP($iplist{$acl[$j]}->addr, $acl[3]); } else { ($i, $intaddress)=setaddress($j, @acl); }
				$ifs{$nameif}=$intaddress;
				push @newzones, "$nameif," . $intaddress->network . "\n";
			}
		}
		when ("route") {
			if (exists $iplist{$acl[2]}) { $route=new NetAddr::IP($iplist{$acl[2]}->addr, $acl[3]); } else { ($i,$route)=setaddress(2, @acl); }
			if (exists $iplist{$acl[4]}) { $nexthop=$iplist{$acl[4]}->addr; } else { $nexthop=$acl[4]; }
			print sroutes "set routing-options static route ". $route->network . " next-hop $nexthop\n" if !defined $options{j};
			print sroutes "\t\troute ". $route->network . " next-hop $nexthop;\n" if defined $options{j};
			print ttables $route->addr . "," . $route->mask . ",$nexthop\n" if defined $options{c};
			push @newzones, "$acl[1]," . $route->network . "\n";
		}
		when ("global") {
			$acl[1] =~ /\((.*)\)/;
			push @globals, "$1,$acl[2]" if $acl[3] eq "interface";
		}
		when ("access-group") {
			if ($acl[2] eq "in") { $inacl{$acl[1]}=$acl[4]; }
			if ($acl[2] eq "out") { $outacl{$acl[1]}=$acl[4]; }
		}
		when ("nat") {
			$acl[1] =~ /\((.*)\)/;
			$from=$1;
			foreach $global (@globals) {
				($to, $num)=split /,/, $global;
				if ($num eq $acl[2] && $from ne $to) {
					if (exists $iplist{$acl[3]}) { $srcaddress=$iplist{$acl[3]}->addr; } else { ($i, $srcaddress)=setaddress(3, @acl); }
					if (!exists $sourcenat{$from}{$to}) {
						$sourcenat{$from}{$to}=$set;
						print nats "set security nat source rule-set source_$set from zone $from\n" if !defined $options{j};
						print nats "\t\t\trule-set source_$set {\n\t\t\t\tfrom zone $from;\n\t\t\t\tto zone $to;\n\t\t\t\t}\n" if defined $options{j};
						print nats "set security nat source rule-set source_$set to zone $to\n" if !defined $options{j};
						$set++;
					}
					$ruleset=$sourcenat{$from}{$to};
					print nats "set security nat source rule-set source_$ruleset rule r$rule match source-address $srcaddress\n" if !defined $options{j};
					print nats "\t\t\trule-set source_$ruleset {\n" if defined $options{j};
					print nats "\t\t\t\trule r$rule {\n\t\t\t\t\tmatch {\n\t\t\t\t\t\tsource-address $srcaddress;\n\t\t\t\t\t\tdestination-address 0.0.0.0/0;\n" if defined $options{j};
					print nats "\t\t\t\t\t}\n\t\t\t\t\tthen {\n\t\t\t\t\t\tsource-nat {\n\t\t\t\t\t\t\tinterface;\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n" if defined $options{j};
					print nats "set security nat source rule-set source_$ruleset rule r$rule match destination-address 0.0.0.0/0\n" if !defined $options{j};
					print nats "set security nat source rule-set source_$ruleset rule r$rule then source-nat interface\n" if !defined $options{j};
					$rule++;
					print ntables "$srcaddress," . $ifs{$to}->addr . ",Any,Same,Zone $from\n" if defined $options{c};
				}
			}
		}
	}
}
if (defined $options{j}) {
	print sroutes "\t}\n}\n";
	print nats "\t\t}\n";
}
close(sroutes);
if (!defined $options{z}) {	
	for ($i=32; $i >= 0; $i--) {
		foreach $zone (@newzones) {
			($name, $network) = split /,/, $zone;
			$net=new NetAddr::IP($network);
			if ($net->masklen == $i) {
				push @zones, $zone;
				print zone $zone;
			}
		}
	}
	close(zone);
} else {
	open (file, "< $options{z}") or die "Can't open Zone file $options{z} for read\n";
	@zones=<file>;
	close(file);
}
open(file, "< $my_path/services.csv") or die "Can't open services file for read\n";
@svcs=<file>;
close(file);
foreach $svc (@svcs) {
	($prot, $name, $jname, $port) = split /,/, $svc;
	chomp($jname);
	chomp($port) if defined $port;
	$service{$prot}{$name}=$jname;
	$svcports{$name}=$port if defined $port;
}
print "\nDestination & Static NATs...\n";
$rule=1;
foreach $line (@all) {
	@acl = split(" ", $line);
	chomp($acl[2]);
	chomp($acl[3]);
	given ($acl[0]) {
		when ("object") {
			$objname=$acl[2] if ($acl[1] eq "network");
		}
		when ($_ eq "subnet" || $_ eq "host") {
			$ip=$iplist{$objname};
			$namelist{$ip}=$objname;
		}
		when ("name") {
			$ip=$iplist{$acl[2]};
			$namelist{$ip}=$acl[2];
		}
		when ("static") {
			if ($acl[2] eq $acl[3]) { next };
			$acl[1] =~ /\((.*)\)/;
			@natint=split(",", $1);
			if ($acl[2] eq "tcp" || $acl[2] eq "udp") { $i=3; $j=5; $dnat=1; } else { $i=2; $j=3; $dnat=0; }
			if ($acl[$i] eq "interface") { $toip=NetAddr::IP->new($ifs{$natint[1]}->addr, "255.255.255.255"); }
			elsif (exists $iplist{$acl[$i]}) { $toip=$iplist{$acl[$i]}; } else { $toip=NetAddr::IP->new($acl[$i]); }
			$from=findzone($toip, @zones);
			if (!defined $options{z}) {
				if ($toip->addr ne $ifs{$from}->addr && $toip->within($ifs{$from})) { print STDERR "Proxy ARP for $toip needed\n"; }
			}
  		if (exists $iplist{$acl[$j]}) { $natip=$iplist{$acl[$j]}; } else { $natip=NetAddr::IP->new($acl[$j]); }
			if ($dnat) {
				$type="destination";
				$srv=$acl[4];
				print nats "\t\tdestination {\n" if defined $options{j};
  			$toport=$service{$acl[2]}{$acl[4]};
  			$natport=$service{$acl[2]}{$acl[6]};
  			print nats "set security nat destination pool pool$rule address $natip" if !defined $options{j};
  			print nats "\t\t\tpool pool$rule {\n\t\t\t\taddress $natip" if defined $options{j};
  			if ($natport ne "") {
  				print nats " port $natport\n" if !defined $options{j};
  				print nats " port $natport;\n\t\t\t\t}\n" if defined $options{j};
  			} else {
  				print nats "\n" if !defined $options{j};
  				print nats ";\n\t\t\t\t}\n" if defined $options{j};
  			}
			} else {
				$type="static";
				$srv="ip";
				print nats "\t\tstatic {\n" if defined $options{j};
			}
  		$natlist{$srv}{$toip}=$natip;
  		if (!exists $natzone{$from}) {
  			$natzone{$from}=1;
				print nats "set security nat $type rule-set " . substr($type,0,6) . "_$from from zone $from\n" if !defined $options{j};
				print nats "\t\t\trule-set " . substr($type,0,6) . "_$from {\n\t\t\t\tfrom zone $from;\n\t\t\t\t}\n" if defined $options{j};
			}
			print nats "set security nat $type rule-set ". substr($type,0,6) . "_$from rule r$rule match destination-address $toip\n" if !defined $options{j};
			print nats "\t\t\trule-set " . substr($type,0,6) . "_$from {\n\t\t\t\trule r$rule {\n\t\t\t\t\tmatch {\n\t\t\t\t\t\tdestination-address $toip;\n" if defined $options{j};
  		if ($dnat) {
  			print nats "set security nat destination rule-set destin_$from rule r$rule match destination-port $toport\n" if ($toport ne "" && !defined $options{j});
  			print nats "\t\t\t\t\t\tdestination-port $toport;\n" if ($toport ne "" && defined $options{j});
  			print nats "set security nat destination rule-set destin_$from rule r$rule then destination-nat pool pool$rule\n" if !defined $options{j};
  			print nats "\t\t\t\t\t}\n\t\t\t\t\tthen {\n\t\t\t\t\t\tdestination-nat pool pool$rule;\n" if defined $options{j};
  		} else {
				print nats "set security nat static rule-set static_$from rule r$rule then static-nat prefix $natip\n" if !defined $options{j};
				print nats "\t\t\t\t\t}\n\t\t\t\t\tthen {\n\t\t\t\t\t\tstatic-nat prefix $natip;\n" if defined $options{j};
			}
			$rule++;
			print nats "\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
			print ntables "Any,Same,$toip,$natip,Zone $from\n" if defined $options{c};
		}
	}
}
print nats "\t}\n}\n" if defined $options{j};
close(nats);
open(objs, "> adds.txt") or die "Can't open adds.txt for write\n";
open(ports, "> apps.txt") or die "Can't open apps.txt for write\n";
open(agroups, "> add-sets.txt") or die "Can't open add-sets.txt for write\n";
open(pgroups, "> app-sets.txt") or die "Can't open app-sets.txt for write\n";
open(rules, "> pols.txt") or die "Can't open pols.txt for write\n";
if (defined $options{j}) {
	if (defined $options{g}) { print objs "security {\n\taddress-book {\n\t\tglobal {\n"; } else { print objs "security {\n\tzones {\n"; }
	if (defined $options{g}) { print agroups "security {\n\taddress-book {\n\t\tglobal {\n"; } else { print agroups "security {\n\tzones {\n"; }
	print ports "applications {\n";
	print pgroups "applications {\n";
	print rules "security {\n\tpolicies {\n";
}
print "\nGroups and Policies...\n";
$policy=1;
$total=0;
$zonelist{"any"}="*** UNKNOWN ***";
if (defined $options{p}) { $pre=$options{p}; } else { $pre=""; }
foreach $line (@all) {
	chomp($line);
	@acl = split(" ", $line);
	chomp($acl[2]);
	chomp($acl[3]);
	given ($acl[0]) {
		when ("object") {
			$objname=$acl[2] if ($acl[1] eq "network");
		}
		when ($_ eq "name" || $_ eq "subnet" || $_ eq "host") {
			if ($_ eq "name") { $ip=$iplist{$acl[2]}; } else { $ip=$iplist{$objname}; }
 			($ip, $name, $hostname)=addressbook($ip, "ip", @zones, @namelist, @natlist);
			if (!exists $zonelist{$hostname}) {
				$zonelist{$hostname}=$name;
				writeaddress($name, $hostname, $ip);
			}
		}
		when ("range") {
			if (!exists $iplist{$acl[1]}) {
				$ip=$acl[1];
                $hostname = $objname;
 				($ip, $name)=rangeaddressbook($ip, @zones);
 			} else { $hostname=$objname; $name=$zonelist{$hostname}; }
			if (!exists $zonelist{$hostname}) {
                $ip1=$acl[1];
                $ip2=$acl[2];
				$zonelist{$hostname}=$name;
				writerangeaddress($name, $hostname, $ip1, $ip2);
			}
		}
		when ("object-group") {
			given ($acl[1]) {
				when ("network") {
					$grp = $acl[2];
					if (defined $options{j}) {
						if (defined $netgroups) {
							print agroups "\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t}\n" if !defined $options{g};
							print agroups "\t\t\t}\n" if defined $options{g};
						}
						print agroups "\t\tsecurity-zone $name {\n\t\t\t\t\taddress-book {\n\t\t\t\t\t\taddress-set $grp {\n" if !defined $options{g};
						print agroups "\t\t\taddress-set $grp {\n" if defined $options{g};
						$netgroups=1;
					}
				}
				when ("service") {
					$grp = $acl[2];
					$protocol = $acl[3]; $group{$grp}=1;
					if (defined $options{j}) {
						if (defined $svcgroups) { print pgroups "\t}\n"; }
						print pgroups "\tapplication-set $grp {\n";
						$svcgroups=1;
					}
				}
			}
		}
		when ("network-object") {
			if ($acl[1] eq "host") { $j=2; $mask="255.255.255.255"; } 
            # address-set sub item of defined addressbook
            elsif ($acl[1] eq "object") {
                $hostname = $acl[2];
                $name = $zonelist{$hostname};
			    if (!defined $options{j}) {
			    	print agroups "set security zones security-zone $name address-book address-set $grp address $hostname\n" if !defined $options{g};
			    	print agroups "set security address-book global address-set $grp address $hostname\n" if defined $options{g};
			    } else {
			    	print agroups "\t\t\t\t\t\t\taddress $hostname;\n" if !defined $options{g};
			    	print agroups "\t\t\t\taddress $hostname;\n" if defined $options{g};
			    }
	 		    print gtables "$grp,$hostname\n" if defined $options{c};
                #fix object-group name and zone mapping of just one item
			    if (!exists $zonelist{$grp}) { $zonelist{$grp}=$name; }
			    elsif ($zonelist{$grp} ne $name) { print STDERR "Group $grp overlaps Zones $zonelist{$grp} and $name\n"; }
                next;
            }
            else { $j=1; $mask=$acl[2]; }
			if (!exists $iplist{$acl[$j]}) {
				$ip=NetAddr::IP->new($acl[$j], $mask);
 				($ip, $name, $hostname)=addressbook($ip, "ip", @zones, @namelist, @natlist);
 			} else { $hostname=$acl[$j]; $name=$zonelist{$hostname}; }
			if (!exists $zonelist{$grp}) { $zonelist{$grp}=$name; }
				elsif ($zonelist{$grp} ne $name) { print STDERR "Group $grp overlaps Zones $zonelist{$grp} and $name\n"; }
			if (!exists $zonelist{$hostname}) {
				$zonelist{$hostname}=$name;
				writeaddress($name, $hostname, $ip);
			}
			if (!defined $options{j}) {
				print agroups "set security zones security-zone $name address-book address-set $grp address $hostname\n" if !defined $options{g};
				print agroups "set security address-book global address-set $grp address $hostname\n" if defined $options{g};
			} else {
				print agroups "\t\t\t\t\t\t\taddress $hostname;\n" if !defined $options{g};
				print agroups "\t\t\t\taddress $hostname;\n" if defined $options{g};
			}
	 		print gtables "$grp,$hostname\n" if defined $options{c};
		}
		when ($_ eq "port-object" || $_ eq "service-object") {
			if ($_ eq "service-object") { $protocol=$acl[1]; $i=2; $j=3; }
			else { $i=1; $j=2; }
			if (exists $service{$protocol}{$acl[$j]}) { $svcname=$service{$protocol}{$acl[$j]}; }
				else {
					($i, $dstport)=setaddress($i, @acl);
					if (!looks_like_number($dstport) && index($dstport, "-")<0) { $dstport=$svcports{$dstport}; }		# Fix idiocy in port/range naming
					given ($protocol) {
						when ("udp") { $svcname="UDP_Port_" . $dstport; }
						when ("tcp") { $svcname="TCP_Port_" . $dstport; }
						when ("tcp-udp") { $svcname="TCP_UDP_Port_" . $dstport; }
					}
					if (!exists $newapp{$protocol}{$acl[$j]}) {
						$newapp{$protocol}{$acl[$j]}=$svcname;
						if ($protocol eq "tcp-udp") {
							print ports "set applications application $svcname term t1 protocol tcp destination-port $dstport\n" if !defined $options{j};
							print ports "set applications application $svcname term t2 protocol udp destination-port $dstport\n" if !defined $options{j};
							print ports "\tapplication $svcname {\n\t\tterm t1 protocol tcp destination-port $dstport;\n" if defined $options{j};
							print ports "\t\tterm t2 protocol udp destination-port $dstport;\n\t}\n" if defined $options{j};
						} else {
							print ports "set applications application $svcname protocol $protocol destination-port $dstport\n" if !defined $options{j};
							print ports "\tapplication $svcname {\n\t\tprotocol $protocol;\n\t\tdestination-port $dstport;\n\t}\n" if defined $options{j};
						}
					}
				}
			print stables "$grp,$svcname\n" if defined $options{c};
			print pgroups "set applications application-set $grp application $svcname\n" if !defined $options{j};
			print pgroups "\t\tapplication $svcname;\n" if defined $options{j};
		}
		when ("access-list") {
			$newsvc="";
			$port="ip";
			if ($acl[2] eq "remark") { next; }
			if (!exists $inacl{$acl[1]} && !exists $outacl{$acl[1]}) { next; }
			if ($acl[2] eq "extended") {
				$j=4; #protocol key or element key
				if ($acl[$j] eq "object-group") { ($i, $newsvc)=setaddress($j, @acl); } else { $i=5; }
			} else {$i=4;$j=3;}
			($i, $srcip)=setaddress($i, @acl);
			if ($acl[$i] eq "gt" || $acl[$i] eq "eq") { $i=$i+2; }
			($i, $dstip)=setaddress($i, @acl);
			$next=$acl[$i];
			if ($next ne "" && $next ne "log" ) {
				($i, $port)=setaddress($i, @acl);
				if (exists $service{$acl[$j]}{$port}) { $newsvc=$service{$acl[$j]}{$port}; }
				elsif (exists $newapp{$acl[$j]}{$port}) { $newsvc=$newapp{$acl[$j]}{$port}; }
				elsif (exists $group{$port}) { $newsvc=$port; }
			}	else {
				given ($acl[$j]) {
					when ("tcp") { $newsvc="junos-tcp-any"; }
					when ("udp") { $newsvc="junos-udp-any"; }
					when ("icmp") { $newsvc="junos-icmp-all"; }
					when ("esp") { $newsvc="ipsec-esp"; }
					when ("ah") { $newsvc="ipsec-ah"; }
					when ("gre") { $newsvc="junos-gre"; }
					when ("115") { $newsvc="junos-l2tp"; }
					when ("ip") { $newsvc="any"; }
				}
			}
			if ($newsvc eq "") {
				if ($acl[$j] eq "icmp" || $acl[$j] eq "ip") { print STDERR "ACL not handled - policy #$policy application $acl[$j]\n$line\n"; }
					else {
						if ($acl[$j] eq "udp") { $newsvc="UDP_Port_" . $port; } else {$newsvc="TCP_Port_" . $port; }
						$newapp{$acl[$j]}{$port}=$newsvc;
						print ports "set applications application $newsvc protocol $acl[$j] destination-port $port\n" if !defined $options{j};
						print ports "\tapplication $newsvc {\n\t\tprotocol $acl[$j];\n\t\tdestination-port $port;\n\t}\n" if defined $options{j};
					}
			}
			if (exists $zonelist{$srcip}) {
				if ($srcip eq "any" && exists $inacl{$acl[1]} && !defined $options{z}) { $fzone=$inacl{$acl[1]}; }
				else { $fzone=$zonelist{$srcip}; }
			} else {
				($srcip, $fzone, $srcname)=addressbook($srcip, "ip", @zones, @namelist, @natlist);
		 		if (!exists $zonelist{$srcname}) {
					$zonelist{$srcname}=$fzone;
					writeaddress($fzone, $srcname, $srcip);		
				}
				$srcip=$srcname;
			}
			if (exists $zonelist{$dstip}) {
				if ($dstip eq "any" && exists $outacl{$acl[1]} && !defined $options{z}) { $tozone=$outacl{$acl[1]}; }
				else { $tozone=$zonelist{$dstip}; }
			} else {
		 		($dstip, $tozone, $dstname)=addressbook($dstip, $port, @zones, @namelist, @natlist);
		 		if (!exists $zonelist{$dstname}) {
					$zonelist{$dstname}=$tozone;
					writeaddress($tozone, $dstname, $dstip);
				}
				$dstip=$dstname;		
			}
			$action=$acl[$j-1];
			$fixed=0;
			if (!defined $options{n}) {
				foreach $rb (@{$rbsrc{$srcip}}) {
					if ($fixed) { last; }
					if ($rb->{FZONE} eq $fzone && $rb->{TZONE} eq $tozone) {
						if ($rb->{SRC} eq $srcip && $rb->{DST} eq $dstip && $rb->{ACT} eq $action && $newsvc ne "any") {
							print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$rb->{POLICY} match application $newsvc\n" if !defined $options{j};
							print rules "\t\tfrom-zone $fzone to-zone $tozone {\n\t\t\tpolicy $pre$rb->{POLICY} {\n\t\t\t\tmatch {\n\t\t\t\t\tapplication $newsvc;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
							print rtables "$pre$rb->{POLICY},,,,,$newsvc\n" if defined $options{c};
							$fixed=1;
							$total++;
						} elsif (!defined $options{s} && $rb->{SRC} eq $srcip && $rb->{SVC} eq $newsvc && $rb->{ACT} eq $action) {
							print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$rb->{POLICY} match destination-address $dstip\n" if !defined $options{j};
							print rules "\t\tfrom-zone $fzone to-zone $tozone {\n\t\t\tpolicy $pre$rb->{POLICY} {\n\t\t\t\tmatch {\n\t\t\t\t\tdestination-address $dstip;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
							print rtables "$pre$rb->{POLICY},,,,$dstip,\n" if defined $options{c};
							$fixed=1;
							$total++;
						}
					}
				}
				if (!$fixed) {
					foreach $rb (@{$rbdest{$dstip}}) {
						if ($fixed) { last; }
						if ($rb->{FZONE} eq $fzone && $rb->{TZONE} eq $tozone) {
							if ($rb->{SRC} eq $srcip && $rb->{DST} eq $dstip && $rb->{ACT} eq $action && $newsvc ne "any") {
								print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$rb->{POLICY} match application $newsvc\n" if !defined $options{j};
								print rules "\t\tfrom-zone $fzone to-zone $tozone {\n\t\t\tpolicy $pre$rb->{POLICY} {\n\t\t\t\tmatch {\n\t\t\t\t\tapplication $newsvc;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
								print rtables "$pre$rb->{POLICY},,,,,$newsvc\n" if defined $options{c};
								$fixed=1;
								$total++;						
							} elsif (!defined $options{s} && $rb->{DST} eq $dstip && $rb->{SVC} eq $newsvc && $rb->{ACT} eq $action) {
								print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$rb->{POLICY} match source-address $srcip\n" if !defined $options{j};
								print rules "\t\tfrom-zone $fzone to-zone $tozone {\n\t\t\tpolicy $pre$rb->{POLICY} {\n\t\t\t\tmatch {\n\t\t\t\t\tsource-address $srcip;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
								print rtables "$pre$rb->{POLICY},,$srcip,,,\n" if defined $options{c};
								$fixed=1;
								$total++;
							}
						}
					}
				}
			}
			if (!$fixed) {
				print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$policy match source-address $srcip destination-address $dstip application $newsvc\n" if !defined $options{j};
				print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$policy then $action\n" if !defined $options{j};
				print rules "\t\tfrom-zone $fzone to-zone $tozone {\n\t\t\tpolicy $pre$policy {\n\t\t\t\tmatch {\n\t\t\t\t\tsource-address $srcip;\n" if defined $options{j};
				print rules "\t\t\t\t\tdestination-address $dstip;\n\t\t\t\t\tapplication $newsvc;\n\t\t\t\t}\n\t\t\t\tthen {\n\t\t\t\t\t$action;\n" if defined $options{j};
				print rules "set security policies from-zone $fzone to-zone $tozone policy $pre$policy then log session-close\n" if ($acl[$i] eq "log" && !defined $options{j});
				print rules "\t\t\t\t\tlog {\n\t\t\t\t\t\tsession-close;\n\t\t\t\t\t}\n" if ($acl[$i] eq "log" && defined $options{j});
				print rules "\t\t\t\t}\n\t\t\t}\n\t\t}\n" if defined $options{j};
				print rtables "$pre$policy,$fzone,$srcip,$tozone,$dstip,$newsvc\n" if defined $options{c};
				$rule={ FZONE=>$fzone, TZONE=>$tozone, POLICY=>$policy++, SRC=>$srcip, DST=>$dstip, SVC=>$newsvc, ACT=>$action };
				push (@{$rbsrc{$rule->{SRC}}}, $rule);
				push (@{$rbdst{$rule->{DST}}}, $rule);
			}
		}
	}
}
if (defined $options{j}) {
	if (defined $options{g}) { print objs "\t\t}\n\t}\n}\n"; } else { print objs "\t}\n}\n"; }
	if (defined $options{g}) { print agroups "\t\t\t}\n\t\t}\n\t}\n}\n"; } else { print agroups "\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t}\n\t}\n}\n"; }
	print ports "}\n";
	print pgroups "\t}\n}\n";
	print rules "\t}\n}\n";
}
close(objs);
close(agroups);
close(pgroups);
close(rules);
close(ports);
print "\n$total rules fixed in total...\n" if ($total);
if (defined $options{c}) {
	close(otables);
	close(gtables);
	close(stables);
	close(rtables);
	close(ntables);
	close(ttables);
}

sub findzone {
	my ($ip, @zones)=@_;
	my $zone, $name, $network;
	foreach $zone (@zones) {
		($name, $network) = split /,/, $zone;
		if ($ip->within(new NetAddr::IP($network))) { last; }
 	}
 	return($name);
}

sub setaddress {
	my ($i, @acl)=@_;
	my $data, $t1, $t2, $p1, $p2;
	my @icmp=("echo","echo-reply","traceroute","unreachable","time-exceeded","source-quench","redirect");

	given ($acl[$i]) {
		when (\%iplist) { $data=$acl[$i++]; }
		when ("object-group")   { $data=$acl[++$i]; }
        #add item to handle object term
		when ("object")   { $data=$acl[++$i]; }
		when ("host")   { if (exists $iplist{$acl[++$i]}) { $data=$acl[$i]; } else { $data=new NetAddr::IP($acl[$i]); } }
		when ("eq")	{ $data=$acl[++$i]; }
		when ("gt") { if (looks_like_number($t1=$acl[++$i])) { $p1=$t1; } else { $p1=$svcports{$t1} };
			$data=$p1 . "-65535"; }
		when ("range")  { 
            if (looks_like_number($t1=$acl[++$i])) { $p1=$t1; } else { $p1=$svcports{$t1} };
		    if (looks_like_number($t2=$acl[++$i])) { $p2=$t2; } else { $p2=$svcports{$t2} };
		    $data=$p1 . "-" . $p2; }
		when ("any")    { $data=$acl[$i]; }
		when (\@icmp)   { $data=$acl[$i]; }
		default	{ $data=new NetAddr::IP($acl[$i++], $acl[$i]); }
	}
	return(++$i, $data);
}

sub addressbook {
	my ($ip, $srv, @zones, @namelist, @natlist)=@_;
	my $zone;
	
	$ip=$iplist{$ip} if (exists $iplist{$ip});
	$ip=$natlist{$srv}{$ip} if (exists $natlist{$srv}{$ip});
	$zone=findzone($ip, @zones);
	if ($ip->masklen eq 32) { $hostname="Host_" . $ip->addr; } else {$hostname="Net_" . $ip->network; }
	$hostname=$namelist{$ip} if (exists $namelist{$ip});
	return($ip, $zone, $hostname);
}

sub rangeaddressbook {
	my ($ip, @zones)=@_;
	$ip=new NetAddr::IP($ip);
	my $zone=findzone($ip, @zones);
	return($ip, $zone);
}

sub writeaddress {
	my ($zone, $hostname, $ip)=@_;

	if (!defined $options{j}) {
		print objs "set security zones security-zone $zone address-book address $hostname $ip\n" if !defined $options{g};
		print objs "set security address-book global address $hostname $ip\n" if defined $options{g};
	} else {
		print objs "\t\tsecurity-zone $zone {\n\t\t\t\t\taddress-book {\n\t\t\t\t\t\taddress $hostname $ip;\n\t\t\t\t\t}\n\t\t}\n" if !defined $options{g};
		print objs "\t\t\taddress $hostname $ip;\n" if defined $options{g};					
	}
	print otables "$hostname,$ip\n" if defined $options{c};
}

sub writerangeaddress {
	my ($zone, $hostname, $start_ip, $end_ip)=@_;

	if (!defined $options{j}) {
		print objs "set security zones security-zone $zone address-book address $hostname range-address $start_ip to $end_ip\n" if !defined $options{g};
		print objs "set security address-book global address $hostname range-address $start_ip to $end_ip\n" if defined $options{g};
	} else {
		print objs "\t\tsecurity-zone $zone {\n\t\t\t\t\taddress-book {\n\t\t\t\t\t\taddress $hostname $ip;\n\t\t\t\t\t}\n\t\t}\n" if !defined $options{g};
		print objs "\t\t\taddress $hostname $ip;\n" if defined $options{g};					
	}
	print otables "$hostname,$start_ip to $end_ip\n" if defined $options{c};
}


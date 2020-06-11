PX2SX - A PIX to Junos configuration conversion tool
====================================================

PX2SX is a conversion utility that takes a PIX or ASA configuration file as input,
and produces a set of output files containing the equivalent Junos configurations
for the SRX platform.

It is NOT intended to perform a hands-off migration of a firewall configuration,
but rather as a way to automate some of the heavy lifting required for larger
rulebase migrations. You will still need to know how to drive Junos and how to
configure your SRX, but it at least ought to mean you don't have to migrate your
1,000 address objects and 500 ACL's one line at a time.

The general usage is: perl px2sx.pl <config.file>

The output files are;
		zones.txt:			Zone names & associated subnets
		adds.txt:				Address objects
		apps.txt:				Application objects
		add-sets.txt:		Address Sets
		app-sets.txt:		Application Sets
		nats.txt:				NAT policies
		pols.txt:				Security policies
		routes.txt:			Static routes

There are some command line flags which are described below. You need Perl 5.012
or later, and the NetAddr::IP module in order for it to run. It should run on most
platforms, but hasn't been extensively tested.

The NetAddr::IP module is (c) Luis E. Muñoz 1999-2007 and (c) Michael Robinton 2006-2010

Note that file handling is somewhat unforgiving, in that it will happily and without
prompting overwrite any output files with the same name if run more than once. You
have been warned.

In order to convert the default applications from PIX to SRX terminology it reads a
services.csv file which is included. The format is simple; protocol,PIX name,Junos name.
Most of the common defaults should be there, but additions should be easy enough.

It will create a zones.txt file with a format of; zone name,subnet/mask (CIDR format)
when it's run. This file can be edited and the result used as input with the -z flag
on subsequent conversion runs in the event that you want to use different zone names,
or want the subnets to end up in a different zone, or whatever. Up to you.

Interface configuration details are not migrated, neither is any VPN configuration
or dynamic routing detail. NATs that simply turn off the automatic translation are not
processed, but it will match the NAT policies to the address objects and fix these in
the Junos output automagically. It does try and replicate the log actions of the
original configuration, the default used is session-close.

Zone matching for address objects is done on a first-match basis, and the zones.txt
file is sorted into longest-mask-first order so that the match will occur as early as
possible. Where it cannot find a named object it will use the pdm definition instead
if this exists, and it will not process an ACL that is not bound to an interface.
It will ignore remark ACL's, and it should handle version 8.x extended ACL's that use
protocol object-groups as well.

Remember that a PIX may often be allowing traffic from a higher to a lower security
level with NAT and GLOBAL statements - you will need to add an explicit permit policy
if you want to replicate this behaviour.

Things you will still have to do yourself include the interface configurations, binding
zones to the interfaces and system-level items like syslog and NTP. It will print
warnings to STDERR about groups that overlap multiple zones, and also if you need to
add proxy-arp statements to the NAT section.

A predefined set of applications (predefined.txt) is included. This contains Junos
application definitions for services that have default PIX names, but not corresponding
Junos ones. There are not many of these - about fifteen at present.

--------------------------------------------------------------------------------

What the flags do:

-c:	Creates a number of .CSV files that contain configuration details. The intended
use for this was to make documentation easier - the files can be opened with Excel
and the results pasted into Word documents. The CSV files are;

		obj-tables.csv:		The address objects
		grp-tables.csv:		The address-set objects
		svc-tables.csv:		The application-set objects
		rule-tables.csv:	The security policies
		nat-tables.csv:		The NAT policies
		route-tables.csv:	The static routes

-g: Write the address objects and address-sets to the global address-book instead of
the zone-based address books. This is useful when you have groups that contain members
from overlapping zones, and don't want to change that - you will still have to duplicate
the required policies yourself in this case.

-j:	Generate the output in Junos config-style syntax (suitable for 'load merge term')
instead of set commands. Pete asked for this and then grumbled incessantly about missing
braces, so this one is his fault.

-n: Switches off the rule combining logic entirely, ie: creates one policy for each ACL.
Without this it will tell you at the end of the run how many ACL's it managed to combine
into previous policies.

-p <STRING>: Prepends the following <STRING> to the policy names (numbers) as they are
generated. This is in case you're wanting to merge the output with existing policies,
or just don't like the numbers - they're not very descriptive.

-s: Partially switches off the policy combining logic, specifically the part that adds
source or destination objects to previously processed policies based on finding a matching
application. With this flag on it will only ever add applications to existing policies,
never source or destination objects - thanks to John for this one.

Use this flag (or -n) if you are concerned about ending up with a policy that permits
more than the original rulebase. The full combining logic seeks to minimise the number
of policies, and the result tends to allow some traffic that wasn't originally permitted.

-z <zone.file>:	Read zone names and subnets from this file instead of creating one based
on the PIX interface names. Using this option does mean that it won't be possible to
automatically work out the right zone for source NATs, proxy ARPs or ACL's that use the
ANY object.

--------------------------------------------------------------------------------

I have no affiliation to either Juniper or Cisco. The existence of this utility does not
suggest or imply that one platform is better than the other. It was created in response
to a specific need that we had, and may or may not be suitable for your purposes.

If you want to extend this thing or contribute to it in some way, you are most welcome.
I'll freely admit the code is not as good as it could be, but then I do have a day job to
do as well. I'll keep an eye on my email for bugs, improvements or suggestions. If you do
find a configuration that causes it to crash (which is not unlikely), then sanitise the
relevant line and send it through - I just may not be able to respond very quickly or even
at all.

Thanks to my employer (Telecom NZ) who allowed this to be released for general use under
the Artistic License 2.0, subject to the terms and conditions outlined below. If you find
this utility useful and travel to New Zealand, you might consider roaming on the XT network
(www.smartphonenetwork.co.nz) in return.

And especially thanks to Drazen, Al, Pete, Stephen, Andrew, John, Luke & Nikolay for helping
by doing what they do.

David Hunter
Gen-i, 11/11/2011
david.hunter@gen-i.co.nz

# This script is provided on an "as is" and "as available" basis and your use of it is at your sole risk.
# Telecom New Zealand Limited (including its subsidiaries, affiliates, employees, directors, officers, agents
# or subcontractors) expressly disclaims all warranties of any kind related to the script, either expressed
# or implied, and all liability for any loss or damage associated with use of the script.

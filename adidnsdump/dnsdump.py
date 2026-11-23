#!/usr/bin/env python
####################
#
# Copyright (c) 2025 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Tool to interact with ADIDNS over LDAP
#
####################
import sys
import argparse
import getpass
import re
import socket
import codecs
from struct import unpack, pack
from impacket.structure import Structure
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, Tls
import ldap3
from impacket.ldap import ldaptypes
import dns.resolver
import dns.name
import datetime
import os
import json
import tempfile
from impacket.krb5.ccache import CCache
from ldap3_ad_auth import bind_kerberos, bind_ntlm

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))



class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self['ipv6Address'])

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = int(self['entombedTime'] / 10)
        try:
            return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)
        except OverflowError:
            return None

def get_dns_zones(connection, root, debug=False):
    connection.search(root, '(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])
    zones = []
    for entry in connection.response:
        if entry['type'] != 'searchResEntry':
            continue
        if debug:
            print(entry['dn'])
        zones.append(entry['attributes']['dc'])
    return zones

def get_dns_resolver(server):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    # Is our host an IP? In that case make sure the server IP is used
    # if not assume lookups are working already
    try:
        if server.startswith('ldap://'):
            server = server[7:]
        if server.startswith('ldaps://'):
            server = server[8:]
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
    except socket.error:
        print_m('Using System DNS to resolve unknown entries. Make sure resolving your target domain works here or specify an IP'\
                ' as target host to use that server for queries')
    return dnsresolver

def ldap2domain(ldap):
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

def print_record(record, ts=False):
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    print_o('Record entry:')
    if ts:
        print('Record is tombStoned (inactive)')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    # A record
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    # NS, CNAME or PTR record
    if record['Type'] in [2, 5, 12]:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        # address.dump()
        print(' - Address: %s' %  address['nameNode'].toFqdn())
    # SRV record
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        # record_data.dump()
        print(' - Priority: %d' %  record_data['wPriority'])
        print(' - Weight: %d' %  record_data['wWeight'])
        print(' - Port: %d' %  record_data['wPort'])
        print(' - Name: %s' %  record_data['nameTarget'].toFqdn())
    # SOA record
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        # record_data.dump()
        print(' - Serial: %d' %  record_data['dwSerialNo'])
        print(' - Refresh: %d' %  record_data['dwRefresh'])
        print(' - Retry: %d' %  record_data['dwRetry'])
        print(' - Expire: %d' %  record_data['dwExpire'])
        print(' - Minimum TTL: %d' %  record_data['dwMinimumTtl'])
        print(' - Primary server: %s' %  record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' %  record_data['zoneAdminEmail'].toFqdn())
    # AAAA record
    if record['Type'] == 28:
        address = DNS_RPC_RECORD_AAAA(record['Data'])
        print(' - Address: %s' % address.formatCanonical())

def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr

def print_operation_result(result):
    if result['result'] == 0:
        print_o('LDAP operation completed successfully')
        return True
    else:
        print_f('LDAP operation failed. Message returned from server: %s %s' %  (result['description'], result['message']))
        return False

# From: https://docs.microsoft.com/en-us/windows/win32/dns/dns-constants
RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    #15: 'MX',
    #16: 'TXT',
    28: 'AAAA',
    33: 'SRV'
}

STATE_VERSION = 1
STATE_SUFFIX = '.state.json'


def record_key(row):
    """Stable identity of an exported record: the tuple (type, name, value)."""
    return '%s\x1f%s\x1f%s' % (row['type'], row['name'], row['value'])


def key_to_row(key):
    rtype, name, value = key.split('\x1f', 2)
    return {'type': rtype, 'name': name, 'value': value}


def default_state_path(outfile):
    return outfile + STATE_SUFFIX


def parse_record_type_filter(filter_arg):
    """
    Parse the --record-types argument into a set of type names as they
    appear in the CSV output. Accepts type names (A, aaaa, ...) and numeric
    type IDs. Raises ValueError on unknown values.
    """
    if not filter_arg:
        return None
    selected = set()
    for token in filter_arg.split(','):
        token = token.strip()
        if not token:
            continue
        if token.isdigit():
            type_id = int(token)
            if type_id not in RECORD_TYPE_MAPPING:
                raise ValueError('Unsupported DNS record type id: %s' % type_id)
            selected.add(RECORD_TYPE_MAPPING[type_id])
        else:
            name = token.upper()
            if name not in RECORD_TYPE_MAPPING.values():
                raise ValueError('Unsupported DNS record type: %s' % token)
            selected.add(name)
    if not selected:
        return None
    return selected


def filter_records(records, allowed_types):
    if not allowed_types:
        return records
    return [row for row in records if row['type'] in allowed_types]


def load_state(path):
    """Return the stored state dict, or None when no/valid state exists."""
    if not path or not os.path.exists(path):
        return None
    try:
        with codecs.open(path, 'r', 'utf-8') as statefile:
            state = json.load(statefile)
    except (ValueError, OSError) as exc:
        print_f('Could not read state file %s (%s), performing full export' % (path, exc))
        return None
    if state.get('version') != STATE_VERSION or not isinstance(state.get('records'), list):
        print_f('State file %s has an unknown format, performing full export' % path)
        return None
    return state


def save_state(path, zone, records, record_types):
    """Atomically persist the fingerprints of the currently exported records."""
    state = {
        'version': STATE_VERSION,
        'zone': zone,
        'record_types': sorted(record_types) if record_types else None,
        'record_count': len(records),
        'records': sorted(record_key(row) for row in records),
    }
    directory = os.path.dirname(os.path.abspath(path))
    tmpfd, tmppath = tempfile.mkstemp(prefix='.adidnsdump-state-', dir=directory)
    try:
        with os.fdopen(tmpfd, 'w', encoding='utf-8') as statefile:
            json.dump(state, statefile, ensure_ascii=False)
        os.replace(tmppath, path)
    except BaseException:
        try:
            os.unlink(tmppath)
        except OSError:
            pass
        raise


def diff_records(current, previous_keys):
    """
    Compare the current export set against the fingerprints stored in a
    previous state. Returns (added, changed, deleted, unchanged) lists of
    row dicts. A value change on the same (type, name) pair is reported as
    a changed record.
    """
    previous = set(previous_keys)
    current_keys = [record_key(row) for row in current]
    current_set = set(current_keys)

    added = []
    changed = []
    unchanged = []
    current_identities = {}
    for row, key in zip(current, current_keys):
        if key in previous:
            unchanged.append(row)
        else:
            identity = (row['type'], row['name'])
            current_identities.setdefault(identity, []).append(key)
            added.append(row)

    previous_identities = {}
    for key in previous:
        row = key_to_row(key)
        previous_identities.setdefault((row['type'], row['name']), []).append(key)

    changed_identities = set(previous_identities).intersection(current_identities)
    if changed_identities:
        added = [
            row for row in added
            if (row['type'], row['name']) not in changed_identities
        ]
        for row, key in zip(current, current_keys):
            identity = (row['type'], row['name'])
            if identity in changed_identities and key not in previous:
                changed.append(row)

    deleted = [
        key_to_row(key) for key in sorted(previous - current_set)
        if (key_to_row(key)['type'], key_to_row(key)['name']) not in changed_identities
    ]
    return added, changed, deleted, unchanged


def write_records_csv(path, records):
    """Write records using the exact same line format as the original tool."""
    with codecs.open(path, 'w', 'utf-8') as outfile:
        outfile.write('type,name,value\n')
        for row in records:
            outfile.write('{type},{name},{value}\n'.format(**row))


def export_records(records, outfile, zone, incremental=False, state_path=None,
                   record_types=None, deleted_file=None, include_deleted=False):
    """
    Handle full/incremental export and state bookkeeping.

    Full export (default): writes all records to outfile, identical to the
    original behavior, and (for incremental runs) stores a state file.
    Incremental export: writes only added/changed records to outfile and,
    when include_deleted is set, deleted records to deleted_file using the
    same CSV format.

    Returns a dict with counts for reporting.
    """
    if state_path is None:
        state_path = default_state_path(outfile)
    if not incremental:
        write_records_csv(outfile, records)
        return {
            'mode': 'full',
            'total': len(records),
            'added': len(records),
            'changed': 0,
            'deleted': 0,
            'unchanged': 0,
            'state_path': None,
            'deleted_file': None,
        }
    state = load_state(state_path)

    if state is None or state.get('zone') != zone or state.get('record_types') != (
            sorted(record_types) if record_types else None):
        reason = 'no previous state' if state is None else 'zone or filter changed'
        print_m('Performing full export (%s)' % reason)
        write_records_csv(outfile, records)
        save_state(state_path, zone, records, record_types)
        return {
            'mode': 'full',
            'total': len(records),
            'added': len(records),
            'changed': 0,
            'deleted': 0,
            'unchanged': 0,
            'state_path': state_path,
            'deleted_file': None,
        }

    added, changed, deleted, unchanged = diff_records(records, state['records'])
    write_records_csv(outfile, added + changed)
    deleted_path = None
    if include_deleted:
        if deleted_file is None:
            base, ext = os.path.splitext(outfile)
            deleted_file = base + '.deleted' + ext
        write_records_csv(deleted_file, deleted)
        deleted_path = deleted_file

    save_state(state_path, zone, records, record_types)
    return {
        'mode': 'incremental',
        'total': len(records),
        'added': len(added),
        'changed': len(changed),
        'deleted': len(deleted),
        'unchanged': len(unchanged),
        'state_path': state_path,
        'deleted_file': deleted_path,
    }

def build_parser():
    parser = argparse.ArgumentParser(description='Query/modify DNS records for Active Directory integrated DNS via LDAP')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host",metavar='HOSTNAME',help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u","--user",metavar='USERNAME',help="DOMAIN\\username for authentication.")
    parser.add_argument("-p","--password",metavar='PASSWORD',help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("--forest", action='store_true', help="Search the ForestDnsZones instead of DomainDnsZones")
    parser.add_argument("--legacy", action='store_true', help="Search the System partition (legacy DNS storage)")
    parser.add_argument("--zone", help="Zone to search in (if different than the current domain)")
    parser.add_argument("--print-zones", action='store_true', help="Only query all zones on the DNS server, no other modifications are made")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show verbose info")
    parser.add_argument("-d", "--debug", action='store_true', help="Show debug info")
    parser.add_argument("-r", "--resolve", action='store_true', help="Resolve hidden records via DNS")
    parser.add_argument("--dns-tcp", action='store_true', help="Use DNS over TCP")
    parser.add_argument("--include-tombstoned", action='store_true', help="Include tombstoned (deleted) records")
    parser.add_argument("--ssl", action='store_true', help="Connect to LDAP server using SSL")
    parser.add_argument("-k", "--kerberos", action='store_true', help="Authenticate with Kerberos")
    parser.add_argument("-dc-ip", help="KDC IP address for Kerberos")
    parser.add_argument("-aesKey", help="AES key for Kerberos authentication")
    parser.add_argument("--referralhosts", action='store_true', help="Allow passthrough authentication to all referral hosts")
    parser.add_argument("--srv", action='store_true', help="Attempt to resolve SRV records")
    parser.add_argument("--dcfilter", action='store_true', help="Use an alternate filter to identify DNS record types")
    parser.add_argument("--sslprotocol", help="SSL version for LDAP connection, can be SSLv23, TLSv1, TLSv1_1 or TLSv1_2")
    parser.add_argument("--outfile", default='records.csv', help="Output file name/path (default: records.csv)")
    parser.add_argument("--incremental", action='store_true',
                        help="Incremental export: only write records added or changed since the previous run "
                             "(tracked in the state file). First run performs a full export")
    parser.add_argument("--state-file",
                        help="State file used for incremental exports (default: <outfile>.state.json)")
    parser.add_argument("-t", "--record-types",
                        help="Comma-separated record types to export, e.g. 'A,AAAA,CNAME' or numeric ids '1,28'")
    parser.add_argument("--include-deleted", action='store_true',
                        help="In incremental mode, also write records removed since the previous run to a deleted CSV")
    parser.add_argument("--deleted-file",
                        help="Output file for deleted records in incremental mode (default: <outfile>.deleted.csv)")
    return parser


def main():
    parser = build_parser()

    args = parser.parse_args()
    try:
        allowed_types = parse_record_type_filter(args.record_types)
    except ValueError as exc:
        print_f(str(exc))
        sys.exit(1)
    #Prompt for password if not set
    authentication = None
    if args.user is not None:
        authentication = ldap3.SASL if args.kerberos else NTLM
        if not '\\' in args.user:
            print_f('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None and not (args.kerberos and (os.environ.get('KRB5CCNAME') or args.aesKey)):
            args.password = getpass.getpass()

    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    if args.ssl:
        s = Server(args.host, get_info=ALL, port=636, use_ssl=True)
    if args.sslprotocol:
        v = {'SSLv23' : 2, 'TLSv1' : 3, 'TLSv1_1' : 4, 'TLSv1_2' : 5}
        if args.sslprotocol not in v.keys():
            parser.print_help(sys.stderr)
            sys.exit(1)
        s = Server(args.host, get_info=ALL, port=636, use_ssl=True, tls=Tls(validate=0, version=v[args.sslprotocol]) )
    if args.referralhosts:
        s.allowed_referral_hosts = [('*', True)]
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication,
                   sasl_mechanism=ldap3.KERBEROS if args.kerberos else None, auto_referrals=False)
    print_m('Binding to host')
    # perform the Bind operation
    try:
        if args.kerberos:
            domain, username = args.user.split('\\', 1)
            tgt = tgs = None
            if os.environ.get('KRB5CCNAME'):
                domain, username, tgt, tgs = CCache.parseFile(domain, username, 'ldap/%s' % args.host)
            bind_kerberos(c, domain=domain, username=username, hostname=args.host,
                          kdc=args.dc_ip or domain, password=args.password or '',
                          aes_key=args.aesKey or '', tgt=tgt, tgs=tgs)
        elif args.user:
            bind_ntlm(c)
        elif not c.bind():
            raise RuntimeError('anonymous bind failed')
    except Exception as exc:
        print_f('Could not bind with specified credentials: %s' % exc)
        sys.exit(1)
    print_o('Bind OK')
    domainroot = s.info.other['defaultNamingContext'][0]
    forestroot = s.info.other['rootDomainNamingContext'][0]
    if args.forest:
        dnsroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
    else:
        if args.legacy:
            dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % domainroot
        else:
            dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot

    if args.print_zones:
        domaindnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot
        zones = get_dns_zones(c, domaindnsroot, args.verbose)
        if len(zones) > 0:
            print_m('Found %d domain DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        forestdnsroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
        zones = get_dns_zones(c, forestdnsroot, args.verbose)
        if len(zones) > 0:
            print_m('Found %d forest DNS zones (dump with --forest):' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        legacydnsroot = 'CN=MicrosoftDNS,CN=System,%s' % domainroot
        zones = get_dns_zones(c, legacydnsroot, args.verbose)
        if len(zones) > 0:
            print_m('Found %d legacy DNS zones (dump with --legacy):' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return

    if args.zone:
        zone = args.zone
    else:
        # Default to current domain
        zone = ldap2domain(domainroot)

    searchtarget = 'DC=%s,%s' % (zone, dnsroot)
    print_m('Querying zone for records')
    sfilter = '(objectClass=*)' if not args.dcfilter else '(DC=*)'
    c.extend.standard.paged_search(searchtarget, sfilter, search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)
    targetentry = None
    if args.resolve:
        dnsresolver = get_dns_resolver(args.host)
    else:
        dnsresolver = None
    outdata = []
    for targetentry in c.response:
        if targetentry['type'] != 'searchResEntry':
            print(targetentry)
            continue
        if not targetentry['attributes']['name']:
            # No permission to view those records
            recordname = targetentry['dn'][3:targetentry['dn'].index(searchtarget)-1]
            if not args.resolve:
                outdata.append({'name':recordname, 'type':'?', 'value': '?'})
                if args.verbose:
                    print_o('Found hidden record %s' % recordname)
            else:
                # Determine if this is likely an SRV record by checking naming pattern
                is_srv = recordname.startswith('_') and '._' in recordname
                
                # Try SRV query first if it looks like an SRV record and --srv option is enabled
                if is_srv and args.srv:
                    try:
                        res = dnsresolver.query('%s.%s.' % (recordname, zone), 'SRV', tcp=args.dns_tcp, raise_on_no_answer=False)
                        if args.verbose:
                            print_o('Resolved as SRV record: %s' % recordname)
                        for answer in res.response.answer:
                            for item in answer:
                                # SRV records have: priority, weight, port, target
                                # Only include the target hostname in the output
                                target = str(item.target)
                                # Remove trailing dot if present
                                if target.endswith('.'):
                                    target = target[:-1]
                                outdata.append({'name':recordname, 'type':'SRV', 'value': target})
                        continue
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, dns.name.EmptyLabel) as e:
                        if args.verbose:
                            print_f(f"SRV lookup failed, trying A record: {str(e)}")
                
                # Fall back to A record query if SRV fails or not an SRV pattern
                try:
                    res = dnsresolver.query('%s.%s.' % (recordname, zone), 'A', tcp=args.dns_tcp, raise_on_no_answer=False)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, dns.name.EmptyLabel) as e:
                    if args.verbose:
                        print_f(str(e))
                    print_m('Could not resolve node %s (probably no A record assigned to name)' % recordname)
                    outdata.append({'name':recordname, 'type':'?', 'value': '?'})
                    continue
                if len(res.response.answer) == 0:
                    print_m('Could not resolve node %s (probably no A record assigned to name)' % recordname)
                    outdata.append({'name':recordname, 'type':'?', 'value': '?'})
                    continue
                if args.verbose:
                    print_o('Resolved hidden record %s' % recordname)
                for answer in res.response.answer:
                    try:
                        outdata.append({'name':recordname, 'type':RECORD_TYPE_MAPPING[answer.rdtype], 'value': str(answer[0])})
                    except KeyError:
                        print_m('Unexpected record type seen: {}'.format(answer.rdtype))
        else:
            recordname = targetentry['attributes']['name']
            if args.verbose:
                print_o('Found record %s' % targetentry['attributes']['name'])

        # Skip tombstoned records unless requested
        if targetentry['attributes']['dNSTombstoned'] and not args.include_tombstoned:
            continue

        for record in targetentry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record)
            # dr.dump()
            # print targetentry['dn']
            if args.debug:
                print_record(dr, targetentry['attributes']['dNSTombstoned'])
            if dr['Type'] == 1:
                address = DNS_RPC_RECORD_A(dr['Data'])
                outdata.append({'name':recordname, 'type': RECORD_TYPE_MAPPING[dr['Type']], 'value': address.formatCanonical()})
            if dr['Type'] in [a for a in RECORD_TYPE_MAPPING if RECORD_TYPE_MAPPING[a] in ['CNAME', 'NS', 'PTR']]:
                address = DNS_RPC_RECORD_NODE_NAME(dr['Data'])
                outdata.append({'name':recordname, 'type':RECORD_TYPE_MAPPING[dr['Type']], 'value': address[list(address.fields)[0]].toFqdn()})
            elif dr['Type'] == 28:
                address = DNS_RPC_RECORD_AAAA(dr['Data'])
                outdata.append({'name':recordname, 'type':RECORD_TYPE_MAPPING[dr['Type']], 'value': address.formatCanonical()})
            # Added SRV record handling
            elif dr['Type'] == 33 and args.srv:  # Only process SRV records if --srv option is enabled
                srv_data = DNS_RPC_RECORD_SRV(dr['Data'])
                # Only include target hostname as requested
                target_host = srv_data['nameTarget'].toFqdn()
                # Remove trailing dot if present
                if target_host.endswith('.'):
                    target_host = target_host[:-1]
                outdata.append({'name':recordname, 'type':RECORD_TYPE_MAPPING[dr['Type']], 'value': target_host})
            elif dr['Type'] not in [a for a in RECORD_TYPE_MAPPING if RECORD_TYPE_MAPPING[a] in ['A', 'AAAA', 'CNAME', 'NS', 'SRV'] or (RECORD_TYPE_MAPPING[a] == 'SRV' and not args.srv)]:
                if args.debug:
                    print_m('Unexpected record type seen: {}'.format(dr['Type']))

            continue
    total_found = len(outdata)
    outdata = filter_records(outdata, allowed_types)
    if allowed_types:
        print_m('Record type filter: %s (%d of %d records kept)'
                % (','.join(sorted(allowed_types)), len(outdata), total_found))
    state_path = args.state_file or default_state_path(args.outfile)
    result = export_records(
        outdata, args.outfile, zone,
        incremental=args.incremental,
        state_path=state_path,
        record_types=allowed_types,
        deleted_file=args.deleted_file,
        include_deleted=args.include_deleted,
    )
    if result['mode'] == 'full':
        print_o(f'Found {total_found} records, saved {result["total"]} to {args.outfile}')
        if args.incremental:
            print_m('State written to %s, next run with --incremental exports only changes'
                    % result['state_path'])
    else:
        print_o('Incremental export: %d added, %d changed, %d deleted (%d unchanged) of %d current records'
                % (result['added'], result['changed'], result['deleted'],
                   result['unchanged'], result['total']))
        print_o('Changes saved to %s' % args.outfile)
        if args.include_deleted:
            print_m('Deleted records saved to %s' % result['deleted_file'])
        print_m('State updated: %s' % result['state_path'])

if __name__ == '__main__':
    main()

#!/usr/bin/env python2

"""
Uses Core's Impacket Library to get the password policy from a windows machine

This is a fork of the original poelnum which is available at
CORE Security Technologies (http://www.coresecurity.com/).

Usage:
./polenum.py -u <username> -p <password> -d <domain/ip> --protocols <protocols>

    Available protocols: ['445/SMB', '139/SMB']

example: polenum aaa:bbb@127.0.0.1
"""
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
from time import strftime, gmtime
import argparse
import sys
import re


def d2b(a):
    tbin = []
    while a:
        tbin.append(a % 2)
        a /= 2

    t2bin = tbin[::-1]
    if len(t2bin) != 8:
        for x in xrange(6 - len(t2bin)):
            t2bin.insert(0, 0)
    return ''.join([str(g) for g in t2bin])


def convert(low, high, lockout=False):
    time = ""
    tmp = 0

    if low == 0 and hex(high) == "-0x80000000":
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        if (low != 0):
            high = abs(high+1)
        else:
            high = abs(high)
            low = abs(low)

        tmp = low + (high)*16**8  # convert to 64bit int
        tmp *= (1e-7)  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
    except ValueError as e:
        return "[-] Invalid TIME"

    if days > 1:
        time += "{0} days ".format(days)
    elif days == 1:
        time += "{0} day ".format(days)
    if hours > 1:
        time += "{0} hours ".format(hours)
    elif hours == 1:
        time += "{0} hour ".format(hours)
    if minutes > 1:
        time += "{0} minutes ".format(minutes)
    elif minutes == 1:
        time += "{0} minute ".format(minutes)
    return time


class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
    }

    def __init__(self, protocols=None,
                 username='', password=''):
        if not protocols:
            protocols = SAMRDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols

    def dump(self, addr):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        print('\n')
        if (self.__username and self.__password):
            print('[+] Attaching to {0} using {1}:{2}'.format(addr,
                                                              self.__username,
                                                              self.__password))
        elif (self.__username):
            print('[+] Attaching to {0} using {1}'.format(addr,
                                                          self.__username))
        else:
            print('[+] Attaching to {0} using a NULL share'.format(addr))

        # Try all requested protocols until one works.
        for protocol in self.__protocols:
            try:
                protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]
            except KeyError:
                print("\n\t[!] Invalid Protocol '{0}'\n".format(protocol))
                sys.exit(1)
            print("\n[+] Trying protocol {0}...".format(protocol))
            rpctransport = transport.SMBTransport(addr, port, r'\samr',
                                                  self.__username,
                                                  self.__password)

            try:
                self.__fetchList(rpctransport)
            except Exception as e:
                print('\n\t[!] Protocol failed: {0}'.format(e))
            else:
                # Got a response. No need for further iterations.
                self.__pretty_print()
                break

    def __fetchList(self, rpctransport):
        dce = DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        resp = samr.hSamrConnect2(dce)
        if resp['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp2 = samr.hSamrEnumerateDomainsInSamServer(
                        dce,
                        serverHandle=resp['ServerHandle'],
                        enumerationContext=0,
                        preferedMaximumLength=500)
        if resp2['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp3 = samr.hSamrLookupDomainInSamServer(
                        dce,
                        serverHandle=resp['ServerHandle'],
                        name=resp2['Buffer']['Buffer'][0]['Name'])
        if resp3['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'],
                                     desiredAccess=samr.MAXIMUM_ALLOWED,
                                     domainId=resp3['DomainId'])
        if resp4['ErrorCode'] != 0:
            raise Exception('Connect error')

        self.__domains = resp2['Buffer']['Buffer']
        domainHandle = resp4['DomainHandle']
        # End Setup

        domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        re = samr.hSamrQueryInformationDomain2(
                    dce, domainHandle=domainHandle,
                    domainInformationClass=domain_passwd)
        self.__min_pass_len = re['Buffer']['Password']['MinPasswordLength'] \
            or "None"
        pass_hist_len = re['Buffer']['Password']['PasswordHistoryLength']
        self.__pass_hist_len = pass_hist_len or "None"
        self.__max_pass_age = convert(
                int(re['Buffer']['Password']['MaxPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MaxPasswordAge']['HighPart']))
        self.__min_pass_age = convert(
                int(re['Buffer']['Password']['MinPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MinPasswordAge']['HighPart']))
        self.__pass_prop = d2b(re['Buffer']['Password']['PasswordProperties'])

        domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        re = samr.hSamrQueryInformationDomain2(
                        dce, domainHandle=domainHandle,
                        domainInformationClass=domain_lockout)
        self.__rst_accnt_lock_counter = convert(
                0,
                re['Buffer']['Lockout']['LockoutObservationWindow'],
                lockout=True)
        self.__lock_accnt_dur = convert(
                0,
                re['Buffer']['Lockout']['LockoutDuration'],
                lockout=True)
        self.__accnt_lock_thres = re['Buffer']['Lockout']['LockoutThreshold'] \
            or "None"

        domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        re = samr.hSamrQueryInformationDomain2(
                        dce, domainHandle=domainHandle,
                        domainInformationClass=domain_logoff)
        self.__force_logoff_time = convert(
                re['Buffer']['Logoff']['ForceLogoff']['LowPart'],
                re['Buffer']['Logoff']['ForceLogoff']['HighPart'])

    def __pretty_print(self):

        PASSCOMPLEX = {
            5: 'Domain Password Complex:',
            4: 'Domain Password No Anon Change:',
            3: 'Domain Password No Clear Change:',
            2: 'Domain Password Lockout Admins:',
            1: 'Domain Password Store Cleartext:',
            0: 'Domain Refuse Password Change:'
        }

        print('\n[+] Found domain(s):\n')
        for domain in self.__domains:
            print('\t[+] {0}'.format(domain['Name']))

        print("\n[+] Password Info for Domain: {0}".format(
                self.__domains[0]['Name']))

        print("\n\t[+] Minimum password length: {0}".format(
                self.__min_pass_len))
        print("\t[+] Password history length: {0}".format(
                self.__pass_hist_len))
        print("\t[+] Maximum password age: {0}".format(self.__max_pass_age))
        print("\t[+] Password Complexity Flags: {0}\n".format(
                self.__pass_prop or "None"))

        for i, a in enumerate(self.__pass_prop):
            print("\t\t[+] {0} {1}".format(PASSCOMPLEX[i], str(a)))

        print("\n\t[+] Minimum password age: {0}".format(self.__min_pass_age))
        print("\t[+] Reset Account Lockout Counter: {0}".format(
                self.__rst_accnt_lock_counter))
        print("\t[+] Locked Account Duration: {0}".format(
                self.__lock_accnt_dur))
        print("\t[+] Account Lockout Threshold: {0}".format(
                self.__accnt_lock_thres))
        print("\t[+] Forced Log off Time: {0}".format(
                self.__force_logoff_time))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', '-u', help='The specified username')
    parser.add_argument('--password', '-p', help='The password of the user')
    parser.add_argument('--domain', '-d', help='The domain or IP')
    parser.add_argument('--protocols', nargs='*',
                        help=str(SAMRDump.KNOWN_PROTOCOLS.keys()))
    parser.add_argument('enum4linux', nargs='?',
                        help='username:password@IPaddress')

    args = parser.parse_args()

    if not args.domain and not args.enum4linux:
        parser.error('argument --domain/-d is required')

    user = args.username
    passw = args.password
    target = args.domain

    if args.enum4linux:
        enum4linux_regex = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)')
        user, passw, target = enum4linux_regex.match(args.enum4linux).groups()

    if args.protocols:
        dumper = SAMRDump(args.protocols, user, passw)
    else:
        dumper = SAMRDump(username=user, password=passw)

    try:
        dumper.dump(target)
        print('\n')
    except KeyboardInterrupt:
        print('\n')
        print("\n\t[!] Ctrl-C Caught, ByeBye\n")
        sys.exit(2)


if __name__ == '__main__':
    main()

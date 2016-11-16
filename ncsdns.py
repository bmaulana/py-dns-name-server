#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

import signal

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"


class ACacheEntry:
    ALPHA = 0.8

    def __init__(self, dict, srtt=None):
        self._srtt = srtt
        self._dict = dict

    def __repr__(self):
        return "<ACE %s, srtt=%s>" % \
               (self._dict, ("*" if self._srtt is None else self._srtt),)

    def update_rtt(self, rtt):
        old_srtt = self._srtt
        self._srtt = rtt if self._srtt is None else \
            (rtt * (1.0 - self.ALPHA) + self._srtt * self.ALPHA)
        logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
                     (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))


class CacheEntry:
    def __init__(self, expiration=MAXINT, authoritative=False):
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CE exp=%ds auth=%s>" % \
               (self._expiration - now, self._authoritative,)


class CnameCacheEntry:
    def __init__(self, cname, expiration=MAXINT, authoritative=False):
        self._cname = cname
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CCE cname=%s exp=%ds auth=%s>" % \
               (self._cname, self._expiration - now, self._authoritative,)


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."),
                 OrderedDict([(DomainName(ROOTNS_DN),
                               CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
                ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                                   CacheEntry(expiration=MAXINT,
                                              authoritative=True))])))])

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])


# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

DNS_ROOT = "199.7.83.42"  # set root DNS server


# recursive function which takes a question entry and sends recursive dns queries to other dns name servers
# to get the IP address of the domain name specified in the question entry
def get_ip_addr(qe, dns_server_to_send):
    # TODO if dns server to send is root ("199.7.83.42"), check whether sub-domain of query exists in cache

    # create DNS query to be sent to authoritative DNS name server
    iq_id = randint(0, 65536)  # random 16 bit int
    iq_header = Header(iq_id, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
    print "\nHeader of query to send to authoritative DNS name server in human readable form is:\n", iq_header
    iq = iq_header.pack() + qe.pack()
    # print "\nQuery to send to DNS server is:\n", hexdump(iq)

    for i in range(3):  # try re-sending to same name server 3x before giving up
        cs.sendto(iq, (dns_server_to_send, 53))  # DNS servers use port 53 by convention

        # get reply from server
        try:
            while True:
                cs.settimeout(2)
                (response, address_not_used,) = cs.recvfrom(512)
                cs.settimeout(None)

                response_header = Header.fromData(response)
                if response_header._id == iq_id:
                    break

        # If no response from server
        except timeout:
            print "\nTimeout, trying to resend query to same authoritative DNS name server"
            cs.settimeout(None)
            if i == 2:
                raise Exception("authoritative DNS name server down")

    # print "\nResponse received from server is:\n", hexdump(response)
    # print "Response header received from DNS server is:\n", hexdump(response_header.pack())
    print "\nResponse header received from authoritative DNS name server in human readable form is:\n", response_header
    print "\nresponse RRs received from authoritative DNS name server are:"
    response_rrs = []
    offset = len(iq)
    for i in range(response_header._ancount + response_header._nscount + response_header._arcount):
        response_rr = RR.fromData(response, offset)
        print response_rr[0]
        response_rrs.append(response_rr[0])
        offset += response_rr[1]

    # If answer exist, send answer (and all RRs from last response received) to client.
    # Else, check authority & additional section to determine next DNS name server to send query.
    if response_header._ancount > 0:
        if response_rrs[0]._type == RR.TYPE_CNAME:
            cname_qe = QE(dn=response_rrs[0]._cname)
            print "CNAME found - starting search for IP address of alias ", response_rrs[0]._cname
            (return_header, return_rrs) = get_ip_addr(cname_qe, DNS_ROOT)  # get IP address of CNAME
            return_header._ancount += 1
            return_rrs.insert(0, response_rrs[0])
            return return_header, return_rrs
        else:
            return response_header, response_rrs

    authority_rrs = response_rrs[:response_header._nscount]
    additional_rrs = response_rrs[-response_header._arcount:]
    tried = []
    for ns in authority_rrs:
        for add in additional_rrs:
            if add._type == RR.TYPE_A and ns._nsdn == add._dn:
                next_name_server_ip = inet_ntoa(add._inaddr)
                print "Next authoritative DNS name server domain is:", ns._nsdn
                print "Next authoritative DNS name server IP is:", next_name_server_ip

                try:
                    return get_ip_addr(qe, next_name_server_ip)
                except Exception, e:
                    if e.message != "authoritative DNS name server down":
                        raise e
                    print "authoritative DNS name server down, trying next one"
                    tried.append(ns)
                    break

    print "\nGlue record not found"
    for ns in authority_rrs:
        if ns in tried:
            continue

        try:
            dns_qe = QE(dn=ns._nsdn)
            print "Finding IP address of authoritative DNS name server ", dns_qe
            (dns_header, dns_rrs) = get_ip_addr(dns_qe, DNS_ROOT)
        except Exception, e:
            if e.message != "authoritative DNS name server down":
                raise e
            print "\nCannot find IP address of ", dns_qe
            continue

        next_name_server_ip = inet_ntoa(dns_rrs[0]._inaddr)
        print "\nNext authoritative DNS name server domain is:", ns._nsdn
        print "Next authoritative DNS name server IP is:", next_name_server_ip
        return get_ip_addr(qe, next_name_server_ip)

    print "\nERROR - Cannot continue DNS lookup (Authority section empty or all name servers specified down)"
    raise Exception("authoritative DNS name server down")


# Register a handler for signal timeout
def timeout_handler(signum, frame):
    raise Exception("timeout")


# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
    # Wait for query
    (data, address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data:
        logger.error("client provided no data")
        continue

    # Parse client query
    # print "\nQuery received from client is:\n", hexdump(data)
    query_header = Header.fromData(data)
    # print "Query header received from client is:\n", hexdump(query_header.pack())
    print "Query header received from client in human readable form is:\n", query_header
    query_qe = QE.fromData(data, 12)
    # print "\nQuery QE received from client is:\n", hexdump(query_qe.pack())
    print "Query QE received from client in human readable form is:\n", query_qe
    print "\nClient's address is:\n", address

    # start timeout timer
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(60)

    try:
        (received_header, received_rrs) = get_ip_addr(query_qe, DNS_ROOT)  # Send iterative queries

        signal.alarm(0)  # disable timeout alarm

        # create DNS response to client
        reply_header = Header(query_header._id, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=query_header._qdcount,
                              ancount=received_header._ancount, nscount=received_header._nscount,
                              arcount=received_header._arcount, qr=True, aa=False, tc=False, rd=True, ra=True)
        reply = reply_header.pack() + query_qe.pack()
        print "\nHeader to send back to client in human readable form is:\n", reply_header
        print "\nQE to send back to client in human readable form is:\n", query_qe
        print "\nRRs to send back to client in human readable form are:"
        for rr in received_rrs:
            print rr
            reply += rr.pack()
            # TODO return glue records for name servers mentioned in authority section
        # print "\nReply to send back to client is:\n", hexdump(reply)

        # TODO: caching
        # TODO: work through page 9 requirements.

        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))

        # send DNS response to client
        ss.sendto(reply, address)

        print "\n\nEND QUERY\n\n"

    except Exception, exc:
        if exc.message == "timeout":
            print "\n\nQUERY TIMEOUT\n\n"
        else:
            raise exc
        signal.alarm(0)  # disable timeout alarm

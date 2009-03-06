#!/usr/bin/env python
# -*- coding: utf8 -*-

# smartdns.py: Part of the SmartDNS package
#
# Copyright 2007 Shun Cox <shuncox(at)gmail.com>
#
# This software is licensed under the terms of the GNU General 
# Public License (GPL). Please see the file COPYING for details.

import SocketServer, socket, string, struct, logging

dnsPort = 53    # dns port number
dns = host = {} # dns & host list
defaultDns = []

logger = logging.getLogger("SmartDns")

##################################################################
# class to manipulate dns packets
##################################################################
class DnsPacket:

    __formatHeader = "!6H"
    __sizeHeader = struct.calcsize(__formatHeader)
    __formatQuery = "!HH"
    __sizeQuery = struct.calcsize(__formatQuery)
    __formatResource = "!HHIH"
    __sizeResource = struct.calcsize(__formatResource)
    
    def __init__(self, data = ""):
        self.buf = data
        #dumpHex(data)
        self.clear()
    
    def clear(self):
        self.qid = 0
        self.name = ""
        self.ans = {}   # dictionary
        self.aa = 0

    def readName(self, startPos):
        name = ""
        qname = self.buf[startPos:]
        compress = False
        off = 1
        while True:
            i = ord(qname[0])
            if i >= 0xc0:
                qname = self.buf[(i * 0x100 + ord(qname[1]) - 0xc000):]
                if compress == False:
                    compress = True
                    off += 1
                continue
            elif i >= len(qname):
                raise ValueError
                break
            elif i == 0:
                break
            elif name != "":
                name += "."
            i += 1
            name += qname[1:i]
            qname = qname[i:]
            if compress == False:
                off += i
        #logger.debug("'%s' = %d" % (name, off))
        return name, off
    
    def writeName(self, name):
        qname = ""
        words = name.split('.')
        for piece in words:
            qname += chr(len(piece))
            qname += piece
        qname += chr(0)
        return qname
        
    def parsing(self):

        if len(self.buf) == 0:
            raise ValueError
            return

        #init
        self.clear()

        pos = 0         # current pointer

        # Get DNS header
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   | ID                                            |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                   QDCOUNT                     |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                   ANCOUNT                     |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                   NSCOUNT                     |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                   ARCOUNT                     |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        self.qid, self.aa, qcount, ans_count, auth_count, add_count = struct.unpack(self.__formatHeader, self.buf[:self.__sizeHeader])
        pos = self.__sizeHeader

        # Query Structure
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                                               |
        #   /                    QNAME                      /
        #   /                                               /
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                    QTYPE                      |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                    QCLASS                     |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        #get name
        self.name, offset = self.readName(pos)
        pos += offset
        
        #get qtype & qclass
        qtype, qclass = struct.unpack(self.__formatQuery, self.buf[pos:(pos + self.__sizeQuery)])
        pos += self.__sizeQuery

        # Get Answers (Resource Record)
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
        #   |                                               |
        #   /                                               / 
        #   /                     NAME                      / 
        #   |                                               | 
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #   |                     TYPE                      |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
        #   |                     CLASS                     | 
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
        #   |                     TTL                       |
        #   |                                               |
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
        #   |                  RDLENGTH                     | 
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        #   /                     RDATA                     /
        #   /                                               /
        #   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        for i in range(0, ans_count):
            namex, offset = self.readName(pos)
            pos += offset
            rtype, rclass, rttl, rlen = struct.unpack(self.__formatResource, self.buf[pos:(pos + self.__sizeResource)])
            pos += self.__sizeResource
            if rtype == 1:
                # if TYPE is 1 then RDATA contains the ipv4 address of the NAME.
                self.ans[namex] = socket.inet_ntoa(self.buf[pos:pos + rlen])
            pos += rlen

    def composing(self):
        self.buf = ""
        qcount = 1
        ans_count = len(self.ans)
        auth_count = 0
        add_count = 0
        qtype = qclass = 1
        rtype = rclass = 1
        rttl = 60
        rlen = 4
        data = struct.pack(self.__formatHeader, self.qid, self.aa, qcount, ans_count, auth_count, add_count)
        data += self.writeName(self.name)
        data += struct.pack(self.__formatQuery, qtype, qclass)
        for key in self.ans:
            data += struct.pack("!H", 0xc00c)
            data += struct.pack(self.__formatResource, rtype, rclass, rttl, rlen)
            data += socket.inet_aton(self.ans[key])
        self.buf = data
        return data

    def get_qid(self):          return self.qid
    def set_qid(self, qid):     self.qid = qid
    def get_name(self):         return self.name
    def set_name(self, name):   self.name = name
    def get_ans(self):          return self.ans
    def set_ans(self, ans):     self.ans = ans
    def get_opcode(self):       return (self.aa >> 11 & 0x0f)
    def set_opcode(self, op):
        self.aa &= 0x7800
        self.aa |= op & 0x0f << 11
    def get_query(self):        return (self.aa & 0x8000 == 0)
    def set_query(self, query):
        if query:
            self.aa &= 0x7fff
        else:
            self.aa |= 0x8000  # it's a query
    def get_rcode(self):        return (self.aa & 0x0f)
    def set_rcode(self, rcode):
        self.aa &= 0xfff0
        self.aa |= rcode & 0x0f
    def get_rd(self):           return (self.aa & 0x0100 != 0)
    def set_rd(self, rd):
        if rd:
            self.aa |= 0x0100
        else:
            self.aa &= 0x0100
    
    qid = property(get_qid, set_qid, None, "qid")
    name = property(get_name, set_name, None, "name")
    ans = property(get_ans, set_ans, None, "answers")
    opcode = property(get_opcode, set_opcode, None, "opcode")
    query = property(get_query, set_query, None, "query")
    rcode = property(get_rcode, set_rcode, None, "rcode")

##################################################################
# class for dns server
##################################################################
class QueryHandler(SocketServer.DatagramRequestHandler):

    def lookupDns(self, name):
        _find = False
        result = []
        for key in dns:
            if key[0] == '.':
                if name.lower().endswith(key):
                    result = dns[key]
                    _find = True
                    break
            elif name.lower() == key:
                result = dns[key]
                _find = True
                break
        if not _find:
            result = defaultDns
        return result

    def lookupHost(self, name):
        result = []
        for key in host:
            if key[0] == '.':
                if name.lower().endswith(key):
                    result = host[key]
                    break
            elif name.lower() == key:
                result = host[key]
                break
        return result
        
    def lookupCache(self, name):
        pass
        return ""

    def handle(self):
        remote = self.client_address;
        data, skt = self.request

        # decoding dns packet
        packet = DnsPacket(data)
        packet.parsing()
        qid = packet.qid
        name = packet.name
        ans = packet.ans

        logger.debug("#%04x query from %s for %s" % (qid, remote, name))

        if not packet.query or packet.opcode != 0:
            logger.warning("...Unsupported!")
            packet.query = False
            packet.ans = {}
            packet.rcode = 5    # or 2 ?
            response = packet.composing()
            #dumpHex(response)
            skt.sendto(response, remote)
            return

        # firstly, search the host list
        hostAddr = self.lookupHost(name)
        if len(hostAddr) != 0:
            # return the packet
            logger.debug("...Host hit!")
            packet.query = False
            packet.ans[name] = hostAddr[0]
            packet.rcode = 0
            response = packet.composing()
            #dumpHex(response)
            skt.sendto(response, remote)
            return

        # secondly, search the cache list
        cacheAddr = self.lookupCache(name)
        if len(cacheAddr) != 0:
            # return the packet
            logger.debug("...Cache hit!")
            packet.query = False
            packet.ans[name] = cacheAddr[0]
            packet.rcode = 0
            response = packet.composing()
            #dumpHex(response)
            skt.sendto(response, remote)
            return
        
        # finally, search the dns list
        dnsAddr = self.lookupDns(name)

        # create a socket & query
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.settimeout(2.0)
        _s.sendto(data, (dnsAddr[0], dnsPort))
        logger.debug("...to %s" % dnsAddr[0])
        
        try:
            response = _s.recv(8192)
        except socket.error, msg:
            logger.error("#%04x socket error: %s" % (qid, msg))
        else:
            # decoding dns packet
            packet = DnsPacket(response)
            packet.parsing()
            qid = packet.qid
            name = packet.name
            ans = packet.ans

            logger.debug("#%04x response from %s : %s" % (qid, dnsAddr[0], ans))

            skt.sendto(response, remote)
        finally:
            _s.close()

##################################################################
# Dump data
def dumpHex(data):
    k = 0
    i = len(data)
    while k < i:
        hline = "%04X: " % k
        cline = ""
        for j in range(0, 16):
            c = data[k]
            hline += "%02x " % ord(c)
            if c.isalnum() == True:
                cline += c
            else:
                cline += '.'
            k += 1
            if k >= i: break
        logger.debug(hline + '\t' + cline)

##################################################################
# Remove comments
def removeComments(str, comchar = '#'):
    i = str.find(comchar)
    if i != -1:
        str = str[:i]
    return str

##################################################################
# Load a list
def loadList(filename):
    lst = {}
    try:
        for line in open(filename, 'r'):
            line = removeComments(line)
            words = line.lower().split()
            if len(words) > 1:
                lst[words[0]] = words[1:]
    except IOError:
        logger.error("Cannot open file %s" % filename)

    return lst

##################################################################
# Create server & start serving.
if __name__ == "__main__":

    format = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(format)
    hdlr = logging.FileHandler("smartdns.log")
    hdlr.setFormatter(format)
    logger.addHandler(console)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

    logger.info("SmartDNS Version 0.2")
    
    logger.info("Loading dns.txt...")
    dns = loadList("dns.txt")
    if not dns.has_key('default'):
        logger.critical("Error: The \'default\' entry in dns.txt is required.")
    else:
        defaultDns = dns['default']
        dns.pop('default')
        logger.debug(dns)

        logger.info("Loading host.txt...")
        host = loadList("host.txt")

        logger.debug(host)

        logger.info("Started.")
        serv = SocketServer.ThreadingUDPServer(("", dnsPort), QueryHandler)
        serv.serve_forever()

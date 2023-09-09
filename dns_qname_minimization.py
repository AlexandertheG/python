#!/usr/bin/env python3

import sys
from dns import resolver
import time
import socket
from dnslib import DNSRecord,DNSHeader,DNSQuestion,RR,A
from scapy.all import DNS, DNSQR, IP, sr1, UDP, DNSRR

def get_resolver_ips(resolver_list):
    tmp_resolver = resolver.Resolver()
    nameservers = []
    for rslv in resolver_list:
        if rslv in memoize_ns:
            nameservers.extend(memoize_ns[rslv])        
        else:
            ans = tmp_resolver.resolve(rslv, 'a')
            memoize_ns[rslv] = []
            for rr in ans.rrset:
                ns_ip = rr.to_text().strip()
                nameservers.append(ns_ip)
                memoize_ns[rslv].append(ns_ip)
    
    return nameservers

def construct_response(quest_rec, response, rec_id):
    dns_hdr = DNSHeader(id=rec_id, qr=1,aa=1,ra=1)
    dns_q = DNSQuestion(quest_rec)
    reply = DNSRecord(dns_hdr, q=dns_q)
        
    for rr_idx in range(response.ancount):
        reply.add_answer(RR(quest_rec,rdata=A(response.an[rr_idx].rdata), ttl=response.an.ttl))
    
    return reply

def resolve_dns_rec(orig_rec, rec, name, resolver_names, part_num, req_id):
    ns = get_resolver_ips(resolver_names)[0]
    if part_num == 0:
        dns_req = IP(dst=ns)/UDP(dport=53)/DNS(qd=DNSQR(qname=name+'.', qtype='A'))
        dns_res = sr1(dns_req, verbose=0)['DNS']
        
        # case: A record lookup of a domain name e.g. cnn.com;
        # look up its authoritativ nameservers in order to get A record of cnn.com 
        if dns_res.an is None:
            dns_req = IP(dst=ns)/UDP(dport=53)/DNS(qd=DNSQR(qname=name+'.', qtype='NS'))
            dns_res = sr1(dns_req, verbose=0)['DNS']
            
            ns_servers = []
            for rr_idx in range(dns_res.nscount):
                ns_servers.append(str(dns_res.ns[rr_idx].rdata, 'UTF-8'))
            return resolve_dns_rec(orig_rec, rec, name, ns_servers, 0, req_id)
        
        if dns_res.an.type == 5:
            cname = str(dns_res.an.rdata, 'UTF-8').split('.')
            cname.pop() # remove '' from array bcs e.g. www.icann.org. split on "."
            return resolve_dns_rec(orig_rec, cname, cname[len(cname) - 1], root_servers, len(cname) - 1, req_id)
        else:
            return construct_response(orig_rec, dns_res, req_id)
    else:
        try:
            dns_req = IP(dst=ns)/UDP(dport=53)/DNS(qd=DNSQR(qname=name+'.', qtype='NS'))
            dns_res = sr1(dns_req, verbose=0)['DNS']
            
            ns_servers = []
            for rr_idx in range(dns_res.nscount):
                ns_servers.append(str(dns_res.ns[rr_idx].rdata, 'UTF-8'))
                
            return resolve_dns_rec(orig_rec, rec, rec[part_num - 1] + '.' + name, ns_servers, part_num - 1, req_id)
        # exception - cut-off is somewhere farther down the name
        except AttributeError as ex:
            return resolve_dns_rec(orig_rec, rec, rec[part_num - 1] + '.' + name, resolver_names, part_num - 1, req_id)
            
                

root_servers = ["a.root-servers.net", "b.root-servers.net", "c.root-servers.net", "d.root-servers.net",
                "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net",
                "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
                "m.root-servers.net"]


UDP_IP = "127.0.0.1"
UDP_PORT = 5533

sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

memoize_ns = {}

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    dns_rec = DNSRecord.parse(data)
    question_arr = []
    for l in dns_rec.questions[0]._qname.label:
        question_arr.append(l.decode("utf-8"))
    
    answer = resolve_dns_rec(".".join(question_arr), question_arr, question_arr[len(question_arr) - 1], root_servers, len(question_arr) - 1, dns_rec.header.id)
    sock.sendto(answer.pack(), addr)

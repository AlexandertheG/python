#!/usr/bin/python3
import sys
import dns
from dns import resolver
def resolve_dns_rec(rec):
    my_resolver = resolver.Resolver()
    my_resolver.nameservers = resolvers
    try:
        res = resolver.query(rec+'.', "A")
        # if the name turns out to be a CNAME
        if res.qname.to_text() != res.canonical_name.to_text():
            cname = res.canonical_name.to_text().split('.')
            cname.pop() # remove '' from array bcs e.g. www.example.com. split on "."
            resolve_dns_rec(cname)
        else:
            print(rec + ":")
            for rr in res.rrset:
                print(rr)
            print()
    except resolver.NXDOMAIN as e:
        pass
                
resolvers = ["8.8.8.8"]
zone = "mydomain.com"
with open("subdomains.txt") as f:
    for name in f.readlines():
        name = name.strip() + "." + zone
        resolve_dns_rec(name)

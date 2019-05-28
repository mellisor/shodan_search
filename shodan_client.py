#!/usr/bin/env python3

import shodan
import pprint
import collections
import netaddr
from time import sleep

def match_test(result):
    print(result)

class Shodan_Client(shodan.Shodan):

    def __init__(self,api_key):
        super().__init__(api_key)

    def filter_hosts(self,iprange,attrs=['ports'],filter=None,on_match=None,wait=1,pages=1):
        """
        Returns host info that matches a certain query
        Also performs a specified function on match
        Args:
            range (str): ip subnet of hosts to scan

            filter (dict): filter by key,value pair.  Value should be a list of wanted attributes
            
            on_match (function): function to perform on match
        """
        matches = {}
        ips = set()
        for p in range(pages):
            sleep(wait)
            result = s.search("net:%s" % (iprange),page=p+1)
            for ip in set([i['ip_str'] for i in result['matches']]):
                ips.add(ip)
        print(ips)
        for ip in ips:
            sleep(wait)
            print(ip)
            try:
                result = self.host([ip])
                matched = True
                # This needs to be redone
                if filter is not None:
                    matched = False
                    for key in filter.keys():
                        for value in filter[key]:
                            result[key] = list(map(lambda x: str(x), result[key]))
                            if value in result[key]:
                                matched = True
                                break
                        if matched:
                            break
                # End needs to be redone
                if matched:
                    item = {}
                    for attr in attrs:
                        item[attr] = result[attr]
                    matches[ip] = item
            except Exception as e:
                print(e)
        return matches

    def compress_ports(self,query,pages=1,wait=1,filter=None):
        """
        Uses default search to gather all hosts' ports into one dict
        """
        hosts = collections.defaultdict(lambda: collections.defaultdict(set))
        for p in range(pages):
            print("Page",p+1)
            results = s.search(query,page=p+1)
            for match in results['matches']:
                if filter:
                    for value in filter:
                        value = int(value)
                        if value == match['port']:
                            hosts[match['ip_str']]['ports'].add(match['port'])
                else:
                    hosts[match['ip_str']]['ports'].add(match['port'])
            sleep(wait)
        return hosts

    def write_csv(self,result,outfile):
        """
        Writes a result from filter_hosts to csv
        """
        import csv
        if len(result.items()) == 0:
            return
        keys = list(list(result.items())[0][1].keys())
        headers = ['ip'] + keys
        with open(outfile,'w+') as f:
            w = csv.DictWriter(f,fieldnames=headers)
            w.writeheader()
            for ip in result.keys():
                row = {'ip': ip}
                for key in keys:
                    row[key] = result[ip][key]
                w.writerow(row)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('range',help="IP range to scan")
    parser.add_argument('-a','--attributes',default='ports',help="Attributes to return")
    parser.add_argument('--ports',action='store_true',help="Only return ports")
    parser.add_argument('-f','--filter',default=None,help="Filter by attributes. Ex: -a ports:22,3389")
    parser.add_argument('-o','--output',help="Output raw json file")
    parser.add_argument('-c','--csv',help="Output CSV file")
    parser.add_argument('-p','--pages',default=1,type=int,help="Number of pages to get results from")
    args = parser.parse_args()

    s = Shodan_Client("YOUR_API_KEY_HERE")

    fltr = None
    if args.filter:
        try: 
            k,v = args.filter.split(':')
            fltr = {k:v.split(',')}
        except Exception:
            print("Syntax error in filter")

    if args.ports:
        if fltr:
            fltr = fltr['ports']
        matches = s.compress_ports("net:%s" % args.range,pages=args.pages,filter=fltr)
    else:
        attrs = args.attributes.split(',')

        matches = s.filter_hosts(args.range,filter=fltr,attrs=attrs,pages=args.pages)
    pprint.pprint(matches)
    if args.csv:
        s.write_csv(matches,args.csv)

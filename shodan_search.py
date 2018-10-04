#!/usr/bin/env python3

import configparser
import os
import argparse
import shodan
import json
import pprint
from time import sleep

def loadConfig(path):
    conf = configparser.ConfigParser()
    conf.read_file(open(path))
    return conf

# Set up argument parser
parser = argparse.ArgumentParser()

parser.add_argument('query',help='Shodan query to perform')

verbose = parser.add_mutually_exclusive_group()

verbose.add_argument('-v','--verbose',dest='verbose',action='store_const',const=True,default=False,help='Prints all found hosts out to console')

verbose.add_argument('-q','--quiet',dest='quiet',action='store_const',const=True,default=False,help='Don\'t print anything out to the console')

attrs = parser.add_mutually_exclusive_group()

attrs.add_argument('-a','--attributes',dest='attributes',help='List of attributes to return, comma seperated')
attrs.add_argument('-s','--specific_attributes',dest='sattributes',help='Return only these attributes, comma seperated')



# Output arguments
parser.add_argument('-f','--filter',dest='filter',help='Filter to apply. Useful if you don\'t have an upgraded shodan account. Only use one filter at a time because I\'m not smart enough. Also must be an iterable because I\'m dumb. \nFormat: -f ports:80,443')
parser.add_argument('-o','--output',dest='output',help='File to output json to')

args = parser.parse_args()

# Declare and parse config file
config_name = 'search.conf'
config_path = os.path.join(os.path.dirname(__file__),config_name)

conf = loadConfig(config_path)

# Get variables from config

api_key = conf.get('API','API_KEY')

# Set up shodan module
try:
    s = shodan.Shodan(api_key)
except Exception as e:
    print(e)

if args.query.split(':')[0] == 'scan':
    s.scan(args.query.split(':')[1])
    exit()

return_attrs = conf.get('SEARCH','default_attributes').split(',')

# Parse return attributes
if args.attributes or args.sattributes:
    if args.sattributes:
        return_attrs = args.sattributes.split(',')
    elif args.attributes.lower() == 'all':
        return_attrs = 'all'
    else:
        return_attrs.extend(args.attributes.split(','))

try:
    # Parse filtered attributes
    sho_filter = {}
    if args.filter:
        (attr,val) = args.filter.split(':')
        sho_filter[attr] = val.split(',')
        if attr not in return_attrs:
            return_attrs.append(attr)
except Exception as e:
    print("Malformed filter")
    exit()

if not args.quiet:
    print("Returning: " + str(return_attrs))

# Make query
if args.query:
    query = args.query

results = s.search(query)
ret_val = {}

# Get host info
for result in results['matches']:
    sleep(1)
    ip = result['ip_str']
    host_info = s.host(ip)
    if return_attrs == 'all':
        return_attrs = host_info.keys()
    ret_val[ip] = {}
    if args.verbose:
        print('\nIP: ' + str(result['ip_str']))
    # Get specified return attributes
    for attr in return_attrs:
        # If the host has the attribute
        if host_info.get(attr):
            if args.verbose:
                print('\t' + attr + ': ' + str(host_info.get(attr)))
            if type(host_info[attr]) is list:
                attr_val = [str(v) for v in host_info[attr]]
            else:
                attr_val = [host_info[attr]]
            # Filter out stuff, only enters this loop if all previous attribute filters met
            if ret_val.get(ip) is not None:
                ret_val[ip][attr] = attr_val
                if attr in sho_filter.keys():
                    delete = True
                    for i_filter in sho_filter[attr]:
                        # If the filter value isn't in the host info, *thicc brooklyn accent* FOGGETTABOUTIT
                        if i_filter in attr_val:
                            delete = False
                    if delete:
                            del(ret_val[ip])
        elif ret_val.get(ip):
            ret_val[ip][attr] = None
    if ret_val.get(ip) and not args.quiet and not args.verbose:
        print('\nIP: ' + ip)
        for key in ret_val[ip]:
            print('\t' + key + ': ' + str(ret_val[ip][key]))

if not args.quiet:
    print("\nMatches: ")
    pprint.pprint(ret_val)

if args.output:
    with open(args.output,'w+') as f:
        json.dump(ret_val,f)

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

s = shodan.Shodan(api_key)

return_attrs = conf.get('SEARCH','default_attributes').split(',')

# Parse return attributes
if args.attributes or args.sattributes:
    if args.sattributes:
        return_attrs = args.sattributes.split(',')
    else:
        return_attrs.extend(args.attributes.split(','))

print(return_attrs)

# Make query
if args.query:
    query = args.query

results = s.search(query)
ret_val = {}

# Parse filtered attributes
sho_filter = {}
if args.filter:
    sho_split = args.filter.split(':')
    sho_filter[sho_split[0]] = sho_split[1].split(',')

# Get host info
for result in results['matches']:
    sleep(1)
    ip = result['ip_str']
    host_info = s.host(ip)
    print(host_info.keys())
    ret_val[ip] = {}
    print('IP: ' + str(result['ip_str']))
    # Get specified return attributes
    for attr in return_attrs:
        # If the host has the attribute
        if host_info.get(attr):
            if type(host_info) is list:
                attr_val = [str(v) for v in host_info[attr]]
            else:
                attr_val = host_info[attr]
            # Filter out stuff
            ret_val[ip][attr] = attr_val
            if attr in sho_filter.keys():
                for i_filter in sho_filter[attr]:
                    # If the filter value isn't in the host info, *thicc brooklyn accent* FOGGETTA BOUTIT
                    if i_filter not in attr_val:
                        del(ret_val[ip])
            else:
                ret_val[ip][attr] = attr_val
        else:
            ret_val[ip][attr] = None
        print(attr + ': ' + str(host_info.get(attr)))

print("\nMatches: ")
pprint.pprint(ret_val)

if args.output:
    with open(args.output,'w+') as f:
        json.dump(ret_val,f)

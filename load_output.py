#!/usr/bin/env python3
import json
import argparse
import pprint

# To interact with this, run python in interactive mode (-i)

parser = argparse.ArgumentParser()
parser.add_argument('file',help='File to load')
args = parser.parse_args()

j = ''
try:
    with open(args.file) as f:
        j = json.load(f)
except FileNotFoundError as e:
    print(e)
    exit()
except Exception as e:
    print('Invalid JSON file')
    exit()

pprint.pprint(j)


#! /usr/bin/env python3

from scapy.all import *
import subprocess
import os
import argparse
from crawler import *
from analyze import *



def parse_args():

     # commandline input arguments
     parser = argparse.ArgumentParser()
     parser.add_argument('-l','--url_list', help="File w/ URLs to scrape")
     parser.add_argument('-r','--num_runs', type=int, default=2, help="Number of runs (default: 2)")     
     parser.add_argument('-i','--interface', help ="network interface")
     
     return parser.parse_args()
     
#would delete this return ^ to make it work   
#not being used, but in case I wanted to enforce at least 1 flag

     """
     args = parser.parse_args()
     if not args.url_list and args.num_runs == 2:
        parser.error(
            "You must provide -r or "
            "-l <url_list> -r <num_runs> [-i <interface>]")
     return args

     """


def main():

    args = parse_args()

    # Defaults
    scrape_file = "monitored_set"
    numRuns = args.num_runs
    interface = args.interface

    # Validate combinations
    if args.url_list and args.interface:
        scrape_file = args.url_list
        print("3-argument mode")

    elif args.url_list:
        scrape_file = args.url_list
        print("2-argument mode")

    else:
        print("running w/ default num of runs: 2")

    #scraping steps only run if user provides input
    print("Scraping...")
    paths = runScrape(scrape_file, numRuns, interface)
    
    print("path[0]")
    print(paths[0])
    
    print(paths)
    analyze(paths[0], paths)
    



if __name__== "__main__":
    main()


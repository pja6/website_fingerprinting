#! /usr/bin/env python3

from scapy.all import *
import argparse
from crawler import *
from analyze import *

#TODO have no way to import pcap/file - everything starts from the crawler list file or hardcoded path

def parse_args():

     # commandline input arguments
     parser = argparse.ArgumentParser()
     group = parser.add_mutually_exclusive_group()


     prog="main.py"
     
     # main.py -run behavior 
                #if analyse only chosen - only need pcap directories - if only unk given, trace_root assumed
                #if crawl only chosen - only need url lists and maybe interface
                #if none chosen - can give all but need file lists and unk directory
     
     group.add_argument('-s','--scraper_mode',action='store_true', help="run scraper.py only | add -l for url list | -r for num runs | -i for interface ")
     parser.add_argument('-l','--url_list', type=str, help="File w/ URLs to scrape e.g. test_file ")
     parser.add_argument('-r','--num_runs', type=int, default=2, help="Number of runs (default: 2)")     
     parser.add_argument('-i','--interface', type=str, help ="network interface")
     parser.add_argument('-t','--tor', action='store_true', help="is the tor running? will default to False")
     group.add_argument('-a','--analyze_mode', action='store_true', help="run analyze.py only | required: -u for unknown pcap directory | add -m for feature directory")
     parser.add_argument('-u','--target_directory', type=str, help="directory with encrypted pcap files")
     parser.add_argument('-m','--known_directory', type=str, default="traces_root", help= "directory with monitored set/named pcap files")
     parser.add_argument('-k','--k_sized_list', type=int, help="size of top k list for comparison")
     parser.add_argument('-c','--threshold', type=float, default=0.0, help="size of allowed threshold for matches" )
     
     
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

     args = parser.parse_args()
     
    # SCRAPER MODE VALIDATION
     if args.scraper_mode:
        if not args.url_list:
            parser.error("--scraper_mode requires -l [--url_list]")

    # ANALYZE MODE VALIDATION
     if args.analyze_mode:
        if not args.target_directory:
            parser.error("--analyze_mode requires -u [--unknown_dir]")

    # FULL PIPELINE (neither mode chosen)
     if not args.scraper_mode and not args.analyze_mode:
        if not args.url_list or not args.target_directory:
            parser.error("Full run requires both -l (url list) and -u (unknown dir), default run and interface will be used if not provided")

     return args
def main():

    args = parse_args()


    # Validate combinations
    if args.scraper_mode:
        print("Running scraper only")
        runScrape(args.url_list, args.num_runs, args.tor, args.interface)
        return

    if args.analyze_mode:
        print("Running analyze only")
        
        k_path = generate_paths(args.known_directory)
        u_path = generate_paths(args.target_directory)

        analyze(k_path, u_path, args.k_sized_list, args.threshold)
        return

    # Full pipeline
    print("Running full pipeline")
        
    print("Scraping...")
    runScrape(args.url_list, args.num_runs, args.tor, args.interface)
    
    u_path = generate_paths(args.target_directory)
    
    analyze("traces_root", u_path, args.k_sized_list, args.threshold)
    



if __name__== "__main__":
    main()


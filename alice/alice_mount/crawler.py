#Paul Aguilar
#! /usr/bin/env python3

from scapy.all import *
import subprocess
import os

#globals
Path=""
path_file=None
file_name=""
dictionary_full=20

#--------------------------------------------Scraping steps start-----------------------------------------------
#Organizational method - builds the test directories 
def makeTestDir(num):
    global Path; 
    if num < 2:
        #cleanup first
        print("clearing previous traces_root...")
        s,o = subprocess.getstatusoutput(f"rm -rf traces_root")
        root_folder=f"traces_root"
        os.makedirs(root_folder, exist_ok=True)
        #easier to delete
        os.chmod(root_folder, 0o777)
        print(f"{root_folder} created")
    
    traces_folder=os.path.join(f"{root_folder}",f"crawl_{num}")

    os.makedirs(traces_folder, exist_ok=True)
    os.chmod(traces_folder, 0o777)

    print(f"{traces_folder} created")

  # Define paths for degree_folder and nonDegree_folder inside the test directory
    Path= traces_folder

#scraping orchestration - uses scrape file to pass in names and url
def runScrape(scrape_file, numRuns=2, interface=None):
    global path_file, file_name, dictionary_full
    run=0
    paths = []
    
    #find the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    #create path to the script
    scrape_file_path = os.path.join(script_dir, scrape_file)

    
    
    # Loop from 1 to numRuns (inclusive)
    for run in range(1, numRuns+1):

        makeTestDir(run)
      
        fo = open(scrape_file_path)
        urlList = fo.readlines()
        #clears file first, in case it's already created
        with open(f'crawl_{run}_paths', 'w') as file:
            pass 
        #saves pcap to correct directory based on index - 1-20 - i know that nondegree starts at 13 
        #in provided scrapefile
        with open(f"crawl_{run}_paths", "a") as path_file:
            print(f"Path file: crawl_{run}_paths created\n")
            for i, url in enumerate(urlList, start=1):
                urlString = url.strip()

                #stop for blank line
                if not urlString:
                    break

                urlString = urlString[:-1]
                urlString = urlString[urlString.rfind("/")+1:]

                #run scrape
                scrape(url, urlString, Path, run, interface)
                run+=1
                dictionary_full=i
            print(f'crawl_{run} pcap files created')
            
            paths.append(path_file.name)
    #for the analyzer to use        
    return paths
            
         

#Actual page scraping 
def scrape(url, pcap, path, runs, interface):
 
    capture = AsyncSniffer(iface=interface, filter="port 443")
    capture.start()

    s,o = subprocess.getstatusoutput(f"curl {url}")
    print(f"scraped {url}")
    s,o = subprocess.getstatusoutput(f"sleep 5")

    r = capture.stop()
    #pathing to add pcap to correct directory
    pcap_path = os.path.join(path,f"{pcap}_{runs}.pcap")
    #writing pcap w/ path
    wrpcap(pcap_path, r)
    #easier to delete
    os.chmod(pcap_path, 0o777)
    path_file.write(f"{pcap_path}\n")
    #print(f'{pcap}.pcap created')

def pause_for_bob(time):
    for i in range(time):
        print(f"waiting...{i} second(s)")
        s,o = subprocess.getstatusoutput(f"sleep 1")    


def main():
    
    timer = 15
    pause_for_bob(timer)
    
    print("starting crawl...")
    
    runScrape("test_file", 1)

    print("\nuser crawl complete\n")

if __name__== "__main__":
    main()

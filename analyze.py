from scapy.all import *


#------------------------------------Start collecting metadata-------------------------------------------------  

def findPayloadSize(pcap):
    total_payload_size=0
    sesh = pcap.sessions()
    max_payload= 0
    #ipList=[]

    #iterate through the list
    for key,value in sesh.items():
        

        for packet in value:
            if TCP in packet:

                #ipList.append(packet[IP].src)

                #rather than attempt to isolate the client ip - will just set a larger threshold to focus
                #on incoming stream
                payloadSize = len(packet[TCP].payload)

                #check if there is a payload
                if payloadSize > 0: 
                    total_payload_size+=payloadSize
        
        max_payload = max(max_payload, total_payload_size)

    return total_payload_size     
        
        
def avg_inter_arrival_time(pcap):
    times = [pkt.time for pkt in pcap if TCP in pkt]

    if len(times) < 2:
        return 0.0

    diffs = [
        t2 - t1
        for t1, t2 in zip(times, times[1:])
    ]


    return sum(diffs) / len(diffs)


def transmission_speed(pcap):
    tcp_packets = [pkt for pkt in pcap if TCP in pkt]

    if len(tcp_packets) < 2:
        return 0.0

    start = tcp_packets[0].time
    end = tcp_packets[-1].time
    duration = end - start

    if duration <= 0:
        return 0.0

    total_bytes = sum(len(pkt[TCP].payload) for pkt in tcp_packets)
    
    

    return total_bytes / duration


#------------------------------------Fill dictionary w/ metadata-------------------------------------------------  



#takes the path file and fills dictionary w/ related metadata accordingly
def create_dict(metadata_dict, readFile=None, readpcap=None):
  
    file = open(f"{readFile}")
    pathList= file.readlines()

    for path in pathList:
        pcap= rdpcap(f"{path.strip()}")
        payload = findPayloadSize(pcap)
        iat = avg_inter_arrival_time(pcap)
        speed= transmission_speed(pcap)


        #steps to get name without relative path for key
        key = path.split('/')[-1]
        key=key.strip()
    
        metadata_dict.setdefault(key, {
                                "_payload_size":None, 
                                "_inter-arrival_time":None,
                                "_trans_speed":None })
        metadata_dict[key]["_payload_size"] = payload
        metadata_dict[key]["_inter-arrival_time"] = iat
        metadata_dict[key]["_trans_speed"] = speed
        
        
def normalize(trace_dict):
    sites_list={}
    
    #group all run data by site
    for trace_name, run in trace_dict.items():
        #just the first _
        site_name = trace_name.rsplit('_',1)[0]
        
        if site_name not in sites_list:
            sites_list[site_name]= []
        sites_list[site_name].append(run)
    
    
    normalized_avgs={}

    #sum per run
    for site_names, runs in sites_list.items():
        total_payloads = 0
        total_times=0
        total_speeds = 0
        
        for run in runs:
            total_payloads += run["_payload_size"]
            total_times += run["_inter-arrival_time"]
            total_speeds += run["_trans_speed"]
        
        num_runs = len(runs)
        
        #avg everything    
        normalized_avgs[site_names] ={
            "_payload_size": total_payloads / num_runs,
            "_inter-arrival_time": total_times / num_runs,
            "_trans_speed": total_speeds / num_runs,
        }
    #print(normalized_avgs)       
    return normalized_avgs

#------------------------------------analyze-------------------------------------------------  



## maybe
def compare_score(user, monitored, weights=None):
    
    if weights is None:
        weights = {
            "_payload_size": 1.0,
            "_inter_arrival_time": 1.0,
            "_trans_speed": 1.0
        }
    score = 0
    for metric in ["_payload_size", "_inter_arrival_time", "_trans_speed"]:
        #print("user metrics")
        print(f"user metric: \n{user}")
        print(f"monitored metric: \n{monitored}")
        diff = abs(user[metric] - monitored[metric])
        score += diff * weights[metric]
    
    return score
    
# matching
def find__matches(user_dict, monitored_dict, threshold=0):
    results = {}
    #updated set to avoid dupes
    matched_keys = set()
    
    #checking against the known set
    for known_site, metrics in monitored_dict.items():
        
        #hold possible matches 
        possible_matches = {}
        
        #going through each of the unknown entries
        for unk_site, metadata in user_dict.items():
            #check for dupes first
            if unk_site not in matched_keys:
                #comparison
                possible_matches[unk_site]=compare_score(metadata, metrics)
            
        best_match = min(possible_matches, key=possible_matches.get)
        best_score = possible_matches[best_match]


        if threshold == 0 or best_score <= threshold:
            results[known_site] = {"best_match": best_match, "score": best_score}
            matched_keys.add(best_match)
            

    return results
            


# match pre-work and formatting
def format_matches(results):
    
  for known_site, match_info in results.items():
        if match_info is None:
            print(f"No match found for {known_site}")
        else:
            best_match = match_info["best_match"]
            best_score = match_info["score"]
            print(f"Matched: {known_site} -> {best_match} (score: {best_score:.2f})")

    

# orchestration method         
def analyze(known_path, target_path=None, target_pcap=None):
    

    target_traces, known_traces= {}, {}
    u_pcap_names, a_pcap_names=[], []
    
    #fill unknown payload & size dictionaries
    create_dict(target_traces, target_path)

    #fill known dictionary lists based on num of runs, if more than 1, updates dictionaries to normalize
    for i, path in enumerate(known_path):
        if i > 0:
            print(f'updating {path}')

        create_dict(known_traces, path)

    #DEBUG print    
    print(f"target trace: \n{target_traces}")
    #print(known_traces)

 
    #normalize the multiple runs
    monitored_set = normalize(known_traces)
    
    #DEBUG print
    #print(monitored_set)
    
    #attempt to match
    matches = find__matches(target_traces, monitored_set)
    
    format_matches(matches)


def main():
    known_path=['wiki_1_paths', 'wiki_2_paths', 'wiki_3_paths', 'wiki_4_paths', 'wiki_5_paths']
    tor_path=['tor_1_paths', 'tor_2_paths', 'tor_3_paths', 'tor_4_paths', 'tor_5_paths']
    analyze(known_path, known_path[0])
    
if __name__ == "__main__":
    main()
    

 
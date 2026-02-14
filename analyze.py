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

#Save pcap to list - eliminate path-file req.
def generate_paths(root_directory="traces_root"):
    paths = []
    
    for dirpath, dirnames, filenames in os.walk(root_directory):

        for name in filenames:
            if name.endswith(".pcap"):
                full_path = os.path.join(dirpath, name)
                paths.append(full_path)
            
                
    return paths

#takes the path file and fills dictionary w/ related metadata accordingly
def create_dict(metadata_dict, pathList):
  
    #file = open(f"{readFile}")
    #pathList= file.readlines()

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
        
        
#------------------------------------ Normalize -------------------------------------------------  

#Needed to update so payload didn't make score massive w/o compromising usefulness of weights in compare_score
# Options were weights ^ | min/max (chose this for 0-1 score 0.3 = 30% difference across all metrics, can then weight) | percentage |     
def calc_min_max(trace_dict):
    min_max = {
        "_payload_size": {"min": float('inf'), "max": float('-inf')},
        "_inter-arrival_time": {"min": float('inf'), "max": float('-inf')},
        "_trans_speed": {"min": float('inf'), "max": float('-inf')}
    }
    
    for metrics in trace_dict.values():
        for metric_name in ["_payload_size", "_inter-arrival_time", "_trans_speed"]:
            val = metrics[metric_name]
            min_max[metric_name]["min"] = min(min_max[metric_name]["min"], val)
            min_max[metric_name]["max"] = max(min_max[metric_name]["max"], val) 
   
    return min_max

# scale all traces in dictionary using provided min/max values        
def apply_scaling(trace_dict, min_max):
    scaled_dict={}
    # Scale each metric to 0-1 range
    
    for site_name, metrics in trace_dict.items():
        scaled_dict[site_name] = {}
        
        for metric_name in ["_payload_size", "_inter-arrival_time", "_trans_speed"]:
            min_val = min_max[metric_name]["min"]
            max_val = min_max[metric_name]["max"]
            
            if max_val - min_val > 0:
                # Scale to 0-1
                scaled_dict[site_name][metric_name] = (
                    (metrics[metric_name] - min_val) / (max_val - min_val)
                )
            else:
                scaled_dict[site_name][metric_name] = 0.0
    
    return scaled_dict


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
    
    min_max = calc_min_max(normalized_avgs)
    scaled_avgs = apply_scaling(normalized_avgs, min_max)
    
    #print(normalized_avgs)       
    return scaled_avgs, min_max

#------------------------------------analyze-------------------------------------------------  


def compare_score(user, monitored, weights=None):
    
    if weights is None:
        weights = {
            "_payload_size": 1.0,
            "_inter-arrival_time": 1.0,
            "_trans_speed": 1.0
        }
    score = 0
    for metric in ["_payload_size", "_inter-arrival_time", "_trans_speed"]:
        #print(f"user metric: \n{user}")
        #print(f"monitored metric: \n{monitored}")
        diff = abs(user[metric] - monitored[metric])
        score += float(diff) * weights[metric]
    
    
    return score/3

#helper method, make top-k list per known site
def get_top_k_per_site(monitored_metrics, user_dict, k=10):
    scores = []

    #compare all unk sites against current known site
    for unk_site, user_metrics in user_dict.items():
        score = compare_score(user_metrics, monitored_metrics)
        scores.append((score, unk_site))
    
    #DBG print
    print(f"scores\n{scores[:k]}")
    
    #sort by best score first
    scores.sort()
    #return top k scores
    return scores[:k]

#which user traces appear in multiple lists
def group_by_target_trace(top_k):
    #update to avoid dupes
    best_matches={}
    
    for known_site, score_list in top_k.items():
        for score, unk_site in score_list:
            #if doesn't exist make it otherwise append
            if unk_site not in best_matches:
                best_matches[unk_site] = []
            best_matches[unk_site].append((score, known_site))
    
    return best_matches
    
def resolve_conflicts(best_matches, threshold):
    matched_set = set()
    results = {}
    disqualified=[]
    
    #try to assign best match 
    for unk_site, candidates in best_matches.items():
        #sort by best score first
        candidates.sort()
        
        matched = False
        #try to find best match first
        for score, known_site in candidates:
            #already matched?
            if known_site not in results and unk_site not in matched_set:
                if threshold == 0 or score <= threshold:
                    results[known_site] = {"best_match": unk_site, "score": score}
                    matched_set.add(unk_site)
                    matched = True
                    break
        if not matched and threshold > 0:
            #good score but over set threshold
            disqualified.append((unk_site, candidates[0]))
        if disqualified:
            print(f"Skipped {len(disqualified)} matches for exceeding threshold: {threshold}")
                
    return results
            
      
#updating matching - greedy approach would limit accuracy - now using a top-k approach per known site
def find_top_k_matches(user_dict, monitored_dict, k=None, threshold=0):
    # size of monitored set is default K
    if k is None:
        k = len(monitored_dict)
        
    #build list for each known site
    top_k_matches = {}
    
    
    for known_site, mon_metrics in monitored_dict.items():
        top_k_matches[known_site] = get_top_k_per_site(mon_metrics, user_dict, k)

    # top k output:
    # {"Wikipedia": [(0.05, "trace1"), (0.08, "trace2"), ...],
    #  "Tor_network": [(0.03, "trace5"), (0.09, "trace1"), ...] }
    
    #find potential conflicts
    best_matches = group_by_target_trace(top_k_matches)
    
    
    #resolve conflicts
    results = resolve_conflicts(best_matches, threshold)
    
    
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
def analyze(known_path, target_path=None, k=None, threshold=0):
    

    target_traces, known_traces= {}, {}
    u_pcap_names, a_pcap_names=[], []
    
    #fill unknown payload & size dictionaries
    create_dict(target_traces, target_path)
        
    ### Monitored set ###
    #fill known dictionary lists based on num of runs, if more than 1, updates dictionaries to normalize
    
    create_dict(known_traces, known_path)
 
    #normalize the multiple runs
    monitored_set, min_max_val = normalize(known_traces)
    
    #now target_traces use the same scale as monitored set, so you don't get:
        # target trace with 150k payload -> becomes 0.58 (using 80k-200k scale)
        # monitored trace with 150k payload -> becomes 0.125 (using 100k-500k scale)
    target_traces_scaled = apply_scaling(target_traces, min_max_val)
    
    #DEBUG print
    #print(monitored_set)
    
    #attempt to match
    matches = find_top_k_matches(target_traces_scaled, monitored_set, 5, threshold)
    
    format_matches(matches)


def main():
    known_path=['wiki_1_paths', 'wiki_2_paths', 'wiki_3_paths', 'wiki_4_paths', 'wiki_5_paths']
    tor_path=['tor_1_paths', 'tor_2_paths', 'tor_3_paths', 'tor_4_paths', 'tor_5_paths']
    
    scraper_traces = generate_paths("traces_root")
    wiki_traces = generate_paths("wiki_root")
    tor_traces = generate_paths("tor_root")
    test_traces = generate_paths("test_files")
    target_traces = generate_paths("target_root")
    #print(wiki_traces)
    analyze(tor_traces, target_traces)
    
  
    
if __name__ == "__main__":
    main()
    

 
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
            "avg_payload": total_payloads / num_runs,
            "avg_ia_time": total_times / num_runs,
            "avg_t_speed": total_speeds / num_runs,
        }
            
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
        print("user metrics")
        print(f"user metric: {user[metric]}")
        print(f"monitored metric: {monitored[metric]}")
        diff = abs(user[metric] - monitored[metric])
        score += diff * weights[metric]
    
    return score
    
    
def find_possible_matches(user_metrics, monitored_dict, threshold=None):
    
    matches = []

    #DEBUG print
    print(f"user metrics:{user_metrics}")
    print(f"monitored_metrics:{monitored_dict}")
    
    for m_name, m_metrics in monitored_dict.items():
        #score = compare_score(user_metrics, m_metrics)
        score= compare_score(user_metrics, monitored_dict)
        if threshold is None or score < threshold:
            matches.append((m_name, score))
    
    # Sort by similarity score (best first)
    matches.sort(key=lambda x: x[1])
    
    return matches

def match_traces(user_dict, monitored_dict, threshold=None):
    
    results = {}
    available_monitored = set(monitored_dict.keys())
    
    for unk_name, unk_metrics in user_dict.items():
        # Only search among available (unmatched) monitored traces
        available_dict = {name: monitored_dict[name] 
                         for name in available_monitored}
        
        possible_matches = find_possible_matches(unk_metrics, available_dict, threshold)
        
        if possible_matches:
            best_match, best_score = possible_matches[0]
            results[unk_name] = (best_match, best_score)
            available_monitored.remove(best_match)
            
            print(f"Matched: {unk_name} -> {best_match} (score: {best_score:.2f})")
            if len(possible_matches) > 1:
                print(f"  Other possibilities: {possible_matches[1:3]}")
        else:
            results[unk_name] = None
            print(f"No match found for {unk_name}")
    
    return results

    

# orchestration method         
def analyze(known_path, target_path=None, target_pcap=None):
    

    target_traces, known_traces= {}, {}
    u_pcap_names, a_pcap_names=[], []
    
    #fill unknown payload & size dictionaries
    create_dict(target_traces, target_path, target_pcap)

    #fill known dictionary lists based on num of runs, if more than 1, updates dictionaries to normalize
    for i, path in enumerate(known_path):
        if i > 0:
            print(f'updating {path}')

        create_dict(known_traces, path)

    #DEBUG print    
    #print(attack_traces)
    #print(known_traces)

 
    #normalize the multiple runs
    monitored_set = normalize(known_traces)
    
    #DEBUG print
    #print(monitored_set)
    
    #attempt to match
    matches = match_traces(target_traces, monitored_set)


def main():
    known_path=['wiki_1_paths', 'wiki_2_paths', 'wiki_3_paths', 'wiki_4_paths', 'wiki_5_paths']
    tor_path=['tor_1_paths', 'tor_2_paths', 'tor_3_paths', 'tor_4_paths', 'tor_5_paths']
    analyze(known_path, known_path[0])
    
if __name__ == "__main__":
    main()
    

 
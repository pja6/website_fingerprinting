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
    print("print interarrival")
    print( sum(diffs/len(diffs)))

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
def create_dict(readFile, metadata_dict):
    names=[]
    file = open(f"{readFile}")
    pathList= file.readlines()
   
    for path in pathList:
        pcap= rdpcap(f"{path.strip()}")
        payload = findPayloadSize(pcap)
        iat = avg_inter_arrival_time(pcap)
        speed= transmission_speed(pcap)

     
        #steps to get name without relative path for key
        pcap_name = path.split('/')[-1]
        pcap_name=pcap_name.strip()
        
        names.append(pcap_name)
        
        metadata_dict.setdefault(pcap_name, {"payload_size":[], "inter-arrival_time":[], "trans_speed":[]})

       
        metadata_dict[pcap_name]["payload_size"].append(payload)
        metadata_dict[pcap_name]["inter-arrival_time"].append(iat)
        metadata_dict[pcap_name]["trans_speed"].append(speed)
        
    return names
        
def normalize(trace_dict):
    
    normalized_run = {
        "avg_payload": Decimal(0),
        "avg_ia_time": Decimal(0),
        "avg_t_speed": Decimal(0)
    }

    #avg individual runs
    for run in trace_dict:
        print(run)
       
        print(trace_dict[run]["inter-arrival_time"])
        normalized_run["avg_payload"] += sum(Decimal(trace_dict[run]["payload_size"])) / Decimal(len(trace_dict[run]["payload_size"]))
        normalized_run["avg_ia_time"] += sum(Decimal(trace_dict[run]["inter-arrival_time"])) / Decimal(len(trace_dict[run]["inter-arrival_time"]))
        normalized_run["avg_t_speed"] += sum(Decimal(trace_dict[run]["trans_speed"])) / Decimal(len(trace_dict[run]["trans_speed"]))
    
    # avg across runs
    num_runs = len(trace_dict)
    normalized_trace = {k: v / num_runs for k, v in normalized_run.items()}
    
    
    return normalized_trace

#------------------------------------analyze-------------------------------------------------  



## maybe
def compare_score(user, monitored, weights=None):
    
    if weights is None:
        weights = {
            "payload_size": 1.0,
            "inter_arrival_time": 1.0,
            "trans_speed": 1.0
        }
    score = 0
    for metric in ["payload_size", "inter_arrival_time", "trans_speed"]:
        print("user metrics")
        print(user[metric])
        diff = abs(user[metric] - monitored[metric])
        score += diff * weights[metric]
    
    return score
    
    
def find_possible_matches(user_metrics, monitored_dict, threshold=None):
    
    matches = []
    
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
def analyze(user_path, attack_path):
    

    user_traces, attack_traces= {}, {}
    u_pcap_names, a_pcap_names=[], []
    
    #fill unknown payload & size dictionaries
    create_dict(user_path, user_traces)

    #fill known dictionary lists based on num of runs, if more than 1, updates dictionaries to normalize
    for i, path in enumerate(attack_path):
        if i > 0:
            print(f'updating {path}')

        create_dict(path, attack_traces)
        
    #print(attack_traces)
  

 
    #normalize the multiple runs
    monitored_set = normalize(attack_traces)
    
    print(monitored_set)
    
    #attempt to match
    matches = match_traces(user_traces, monitored_set)


def main():
    analyze()
    
if __name__ == "__main__":
    main()
    

 
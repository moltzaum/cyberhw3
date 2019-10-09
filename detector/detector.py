from datetime import datetime

_caught_ips = {}

def detect(channel):

    while True:
         
        table = channel.get()
        
        # ip -> (sec_count_list, min_count_list, total_count)
        ip_connections = {}
        get_counts(table, ip_connections)
        
        channel.put(table)
        
        for ip, counts in ip_connections.items():
            seconds, minutes, total_count = counts
            
            if seconds[0] > 5 or min_fanout[0] > 100 or total_count > 300:
                report_ip(ip, seconds, minutes, total_count)

# for each ip in the table, what is the frequency of occurances per second, per minute, and total?
# mutates the ip_connections dictionary to contain the new count information
# only information from the last 5 minutes is considered, the table is updated if an entry should be deleted
def get_counts(table, ip_connections):
    
    del_keys = []
    for key, time in table.items():
        
        diff_seconds = int((datetime.now() - time).total_seconds())
        diff_minutes = int(diff_seconds / 60)
        ip = key[0]
        
        if diff_seconds >= 300:
            del_keys.append(key)
        else:
            # seconds is an array of 300 for 1 second intervals across 5 minutes
            # minutes is an array of 5 for 1 minute intervals across 5 minutes
            seconds, minutes, total_count = ip_connections.get(ip, ([0] * 300, [0] * 5, 0))
            seconds[diff_seconds] += 1
            minutes[diff_minutes] += 1
            ip_connections[ip] = (seconds, minutes, total_count + 1)

    # items can't be deleted from a dictionary as you iterate over it
    for key in del_keys:
        del table[key]

# prints the ip information to the screen
# waits a minute for already-reported ips to avoid spam
def report_ip(ip, sec_fanout, min_fanout, total_count):
    
    if ip in _caught_ips:
        elapsed_min = int((_caught_ips[ip] - datetime.now()).total_seconds() / 60)
        if elapsed_min == 0:
            return
    
    avg = lambda lst: sum(lst) / len(lst)

    reason = ""
    if sec_fanout > 5:
        reason = "avg fan-out per second exceeds 5" 
    elif min_fanout > 100:
        reason = "avg fan-out per minute exceeds 5" 
    elif total_count > 300:
        reason = "number of first-connections in the last 5 minutes exceeds 300" 
    
    message = (
        "port scanner detected on source IP %s\n"
        "avg fan-out per second: %s, avg fan-out per min: %s, fan-out per 5 min: %s\n"
        "reason: %s")
    print(message % (ip, avg(seconds), avg(minutes), total_count, reason))
    _caught_ips[ip] = datetime.now()



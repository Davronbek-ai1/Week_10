def analyze_logs(log_entries):
    error_dict = {}
    for i in log_entries:
        parts2 = i.split("-")
        parts = []
        for j in parts2:
            j = j.strip()
            parts.append(j)
        if parts[1] == "200":
            continue
        else:
            if parts[0] in error_dict:
                error_dict[parts[0]] += 1
            else:
                error_dict[parts[0]] = 1
    return error_dict

def flag_suspicious_ips(error_dict):
    print(f"Error Counts:")
    for ip, number in error_dict.items():
        print(f"{ip}: {number}")    
    print("-"*20)
    for ip, number in error_dict.items():
        if number >= 3:
            print(f"SECURITY ALERT: {ip} has {number} errors.")


log_entries = [
    "192.168.1.1 - 200",
    "10.0.0.5 - 404",
    "192.168.1.1 - 200",
    "10.0.0.5 - 500",
    "172.16.0.1 - 404",
    "10.0.0.5 - 404",
    "192.168.1.1 - 500",
    "10.0.0.5 - 404"
]

flag_suspicious_ips(analyze_logs(log_entries))

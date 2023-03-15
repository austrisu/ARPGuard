# ARPGuardian

sniffer.py is a Python script that monitors the ARP table of your local network for any new IP addresses that are not whitelisted. If a rogue IP address is detected, the script can perform various actions depending on the command-line options provided.

## Requirements

-   Python 3.6 or later
-   Paramiko library
    To install the Paramiko library, run:

```
pip install paramiko
```

## Configuration

Before running the script, modify the config.json file to include your whitelist IP addresses, SSH credentials, and listener configuration.

Example:

```
{
  "whitelist": ["192.168.1.1", "192.168.1.2"],
  "credentials": [
    {
      "username": "root",
      "password": "random123"
    }
  ],
  "listener": {
    "username": "your_username",
    "ip_address": "YOUR_IP_ADDRESS",
    "port": "YOUR_PORT"
  }
}
```

## Usage

Run the script using the following command:

```
python arp_monitor.py
Command-Line Options
-s, --ssh: Enable SSH connection to rogue devices.
-r, --reverse: Set up a reverse shell connection by creating the /tmp/systemd.sh file on the rogue device and running it in the background.
-k: log out rest of the users from roug device.
```

To use these options, provide them as arguments when running the script. For example, to enable SSH connections and set up a reverse shell, run:

```
python arp_monitor.py --ssh --reverse
```

## Features

Monitors the local network ARP table for new IP addresses that are not whitelisted.

-   Establishes an SSH connection to the rogue device.
-   Sets up a reverse shell connection to the rogue device.
-   Disconnects rest of the users from remote device.
    Logs the detected IP addresses, MAC addresses, and timestamps.

## Create listener

```
nc -lvnp 12345
```

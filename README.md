# SDN Access Control System using POX

## Overview
This project implements an Access Control System using Software Defined Networking (SDN) with the POX controller. The system restricts network access based on predefined whitelist rules and dynamically manages packet forwarding.

## Features
- Whitelist-based access control
- Unauthorized hosts are blocked
- Dynamic flow rule installation
- Learning switch behavior
- Real-time packet monitoring with logs

## Technologies Used
- Python
- POX SDN Controller
- OpenFlow Protocol
- Mininet (for network simulation)

## System Design

The controller enforces access policies as follows:

- Allowed Hosts: h1, h2, h3
- Blocked Host: h4

The controller checks each incoming packet:
- If the source is in the whitelist -> allow and install flow rule
- If the source is not in the whitelist -> block the packet

## How It Works

1. The switch connects to the POX controller.
2. The controller listens for incoming packets.
3. For each packet:
   - Verifies the source MAC address
   - Applies access control policy
4. If allowed:
   - Installs a flow rule in the switch
   - Future packets are forwarded without controller intervention
5. If blocked:
   - Packet is dropped immediately

## Sample Log Output

- ALLOWED: Packet forwarded and rule installed
- BLOCKED: Packet dropped due to unauthorized source
- Flooding: Packet broadcast when destination is unknown

## Author
Rushieswar Reddy M

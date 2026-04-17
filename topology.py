#!/usr/bin/env python3
"""
SDN-Based Access Control System — Mininet Topology
Course: UE24CS252B | Project 11
Controller: POX | OpenFlow 1.0
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_network():
    net = Mininet(
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    info("*** Adding Remote POX Controller\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    info("*** Adding Switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow10")

    info("*** Adding Hosts\n")
    h1 = net.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24")
    h2 = net.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24")
    h3 = net.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3/24")
    h4 = net.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4/24")

    info("*** Adding Links\n")
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)
    net.addLink(h4, s1, bw=10)

    info("*** Starting Network\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("\n")
    info("=" * 60 + "\n")
    info("  SDN Access Control Topology Ready\n")
    info("  Authorized  : h1, h2, h3\n")
    info("  Unauthorized: h4\n")
    info("=" * 60 + "\n\n")

    run_tests(net)

    info("*** Opening Mininet CLI\n")
    CLI(net)

    info("*** Stopping Network\n")
    net.stop()


def run_tests(net):
    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")

    info("\n" + "-" * 60 + "\n")
    info("TEST SCENARIO 1 — Authorized hosts communicate\n")
    info("-" * 60 + "\n")

    info("h1 → h2 ping (expected: SUCCESS)\n")
    result = h1.cmd("ping -c 3 -W 2 10.0.0.2")
    info(result + "\n")

    info("h2 → h3 ping (expected: SUCCESS)\n")
    result = h2.cmd("ping -c 3 -W 2 10.0.0.3")
    info(result + "\n")

    info("h3 → h1 ping (expected: SUCCESS)\n")
    result = h3.cmd("ping -c 3 -W 2 10.0.0.1")
    info(result + "\n")

    info("-" * 60 + "\n")
    info("TEST SCENARIO 2 — Unauthorized host is blocked\n")
    info("-" * 60 + "\n")

    info("h4 → h1 ping (expected: FAIL / blocked)\n")
    result = h4.cmd("ping -c 3 -W 2 10.0.0.1")
    info(result + "\n")

    info("h4 → h2 ping (expected: FAIL / blocked)\n")
    result = h4.cmd("ping -c 3 -W 2 10.0.0.2")
    info(result + "\n")

    info("-" * 60 + "\n")
    info("TEST SCENARIO 3 — iperf throughput (authorized path)\n")
    info("-" * 60 + "\n")

    info("Starting iperf server on h2...\n")
    h2.cmd("iperf -s -u &")
    import time; time.sleep(1)

    info("h1 → h2 UDP iperf (10s):\n")
    result = h1.cmd("iperf -c 10.0.0.2 -u -t 10 -b 5M")
    info(result + "\n")
    h2.cmd("kill %iperf")

    info("-" * 60 + "\n")
    info("REGRESSION TEST — Policy consistency after re-check\n")
    info("-" * 60 + "\n")

    info("h1 → h2 (should still work):\n")
    result = h1.cmd("ping -c 2 -W 2 10.0.0.2")
    lost_line = [l for l in result.splitlines() if "packet loss" in l]
    info((lost_line[0] if lost_line else result) + "\n")

    info("h4 → h3 (should still be blocked):\n")
    result = h4.cmd("ping -c 2 -W 2 10.0.0.3")
    lost_line = [l for l in result.splitlines() if "packet loss" in l]
    info((lost_line[0] if lost_line else result) + "\n")

    info("-" * 60 + "\n\n")


if __name__ == "__main__":
    setLogLevel("info")
    build_network()

"""
SDN-Based Access Control System
Course: UE24CS252B | Project 11
Controller: POX | OpenFlow 1.0
"""

from pox.core import core
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
import datetime

log = core.getLogger()

# ─────────────────────────────────────────
#  WHITELIST — only these MACs can communicate
# ─────────────────────────────────────────
WHITELIST_MACS = {
    EthAddr("00:00:00:00:00:01"),   # h1 — authorized
    EthAddr("00:00:00:00:00:02"),   # h2 — authorized
    EthAddr("00:00:00:00:00:03"),   # h3 — authorized
    # h4 (00:00:00:00:00:04) — NOT in whitelist = blocked
}

class AccessControl(object):

    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)
        log.info("Switch %s connected.", dpid_to_str(connection.dpid))

    def _log(self, action, src, dst, reason=""):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        log.info("[%s] %s | src=%s dst=%s | %s", ts, action, src, dst, reason)

    def _install_drop_rule(self, src_mac):
        """Install a proactive drop rule for unauthorized host."""
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 120
        msg.match.dl_src = src_mac
        # No actions = DROP
        self.connection.send(msg)

    def _install_forward_rule(self, src_mac, dst_mac, in_port, out_port):
        """Install a forwarding rule for authorized hosts."""
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 30
        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        msg.match.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_packet(self, packet_in, out_port):
        """Forward the current packet."""
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet   = event.parsed
        src_mac  = packet.src
        dst_mac  = packet.dst
        in_port  = event.port

        # ── ACCESS CONTROL CHECK ──────────────────────────
        if src_mac not in WHITELIST_MACS:
            self._log("BLOCKED", src_mac, dst_mac, "src not in whitelist")
            self._install_drop_rule(src_mac)
            return   # drop packet

        # ── LEARNING SWITCH for authorized hosts ──────────
        self.mac_to_port[src_mac] = in_port

        if dst_mac in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac]
            self._log("ALLOWED", src_mac, dst_mac,
                      "rule installed → port %d" % out_port)
            self._install_forward_rule(src_mac, dst_mac, in_port, out_port)
            self._send_packet(event.ofp, out_port)
        else:
            self._log("ALLOWED", src_mac, dst_mac, "flooding")
            self._send_packet(event.ofp, of.OFPP_FLOOD)


class AccessControlLauncher(object):
    def __init__(self):
        core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
        log.info("=" * 50)
        log.info("  Access Control System Ready")
        log.info("  Whitelisted: h1, h2, h3")
        log.info("  Blocked: h4 (unauthorized)")
        log.info("=" * 50)

    def _handle_ConnectionUp(self, event):
        AccessControl(event.connection)


def launch():
    core.registerNew(AccessControlLauncher)

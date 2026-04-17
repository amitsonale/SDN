from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

# Host database: MAC -> {port, ip}
host_db = {}

# Firewall rule: block h1 -> h3
BLOCKED_SRC_IP = "10.0.0.1"
BLOCKED_DST_IP = "10.0.0.3"


def show_hosts():
    log.info("----- Host Table -----")
    if not host_db:
        log.info("No hosts discovered yet")
        return

    for mac, data in host_db.items():
        port = data["port"]
        ip = data["ip"]
        log.info("MAC: %s | IP: %s | Port: %s", mac, ip, port)


def _handle_ConnectionUp(event):
    log.info("Switch %s connected", event.dpid)


def _handle_PacketIn(event):  //This function handles every packet that does not match any rule in the switch
    packet = event.parsed
    if not packet:
        return

    src_mac = packet.src
    dst_mac = packet.dst
    in_port = event.port

    ip_packet = packet.find('ipv4')

    updated = False

    # Host discovery
    if src_mac not in host_db:
        host_db[src_mac] = {"port": in_port, "ip": None}
        updated = True
        log.info("Host JOINED: MAC=%s Port=%s", src_mac, in_port)

    if host_db[src_mac]["port"] != in_port:
        host_db[src_mac]["port"] = in_port
        updated = True

    if ip_packet:
        src_ip = str(ip_packet.srcip)
        if host_db[src_mac]["ip"] != src_ip:
            host_db[src_mac]["ip"] = src_ip
            updated = True

    if updated:
        show_hosts()

    # Firewall logic
    if ip_packet:
        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        if src_ip == BLOCKED_SRC_IP and dst_ip == BLOCKED_DST_IP:
            log.info("Blocking traffic %s -> %s", src_ip, dst_ip)

            msg = of.ofp_flow_mod()
            msg.priority = 65535

            msg.match = of.ofp_match()
            msg.match.dl_type = 0x0800
            msg.match.nw_src = IPAddr(src_ip)
            msg.match.nw_dst = IPAddr(dst_ip)

            msg.idle_timeout = 0
            msg.hard_timeout = 0

            event.connection.send(msg)
            return

    # Learning switch logic (FIXED for TCP/iperf)
    if dst_mac in host_db:
        out_port = host_db[dst_mac]["port"]

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()

        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        msg.match.in_port = in_port

        msg.priority = 10
        msg.idle_timeout = 5
        msg.hard_timeout = 10

        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

        packet_out = of.ofp_packet_out()
        packet_out.data = event.ofp
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(packet_out)

    else:
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)


def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Firewall + Learning Switch + Host Discovery Started")

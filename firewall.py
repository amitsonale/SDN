from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()  # logging

host_db = {}  # MAC -> {port, ip}

BLOCKED_SRC_IP = "10.0.0.1"
BLOCKED_DST_IP = "10.0.0.3"  # firewall rule


def show_hosts():
    log.info("----- Host Table -----")
    if not host_db:
        log.info("No hosts discovered yet")
        return

    for mac, data in host_db.items():
        log.info("MAC: %s | IP: %s | Port: %s",
                 mac, data["ip"], data["port"])  # print hosts


def _handle_ConnectionUp(event):
    log.info("Switch %s connected", event.dpid)  # switch connected


def _handle_PacketIn(event):
    # packet from switch (no rule)

    packet = event.parsed
    if not packet:
        return  # ignore

    src_mac = packet.src
    dst_mac = packet.dst
    in_port = event.port

    ip_packet = packet.find('ipv4')  # check IPv4
    updated = False


    # ---- host discovery ----
    if src_mac not in host_db:
        host_db[src_mac] = {"port": in_port, "ip": None}  # new host
        updated = True

    if host_db[src_mac]["port"] != in_port:
        host_db[src_mac]["port"] = in_port  # update port
        updated = True

    if ip_packet:
        src_ip = str(ip_packet.srcip)
        if host_db[src_mac]["ip"] != src_ip:
            host_db[src_mac]["ip"] = src_ip  # update IP
            updated = True

    if updated:
        show_hosts()  # show table


    # firewall
    if ip_packet:
        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        if src_ip == BLOCKED_SRC_IP and dst_ip == BLOCKED_DST_IP:
            msg = of.ofp_flow_mod()
            msg.priority = 65535  # high priority

            msg.match = of.ofp_match()
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_src = IPAddr(src_ip)
            msg.match.nw_dst = IPAddr(dst_ip)

            msg.idle_timeout = 0
            msg.hard_timeout = 0

            event.connection.send(msg)  # drop
            return


    # learning switch
    if dst_mac in host_db:
        out_port = host_db[dst_mac]["port"]  # known dest

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()

        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        msg.match.in_port = in_port

        msg.priority = 10
        msg.idle_timeout = 5
        msg.hard_timeout = 10

        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)  # install rule

        packet_out = of.ofp_packet_out()
        packet_out.data = event.ofp
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(packet_out)  # send packet

    else:
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)  # flood


def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Controller started")  # start

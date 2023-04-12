from scapy.all import *
import dpkt
import datetime
import socket
import binascii
from dpkt.compat import compat_ord
import sys
import traceback
def portscan(filename):
    dst_ports = {}
    i = 0

    for packet in rdpcap(filename):
        if (not packet.haslayer(IP)):
            i = i+1
            continue

        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else: 
            i = i+1
            continue
        
        ip = packet[IP].dst

        if ip not in dst_ports:
            dst_ports[ip] = {}
            dst_ports[ip][port] = i
        else:
            if port not in dst_ports[ip].keys():
                dst_ports[ip][port] = i

        i = i+1

    for ip in dst_ports.keys():
        if len(dst_ports[ip].keys()) >= 100:
            print('Port scan!')
            print('Dst IP:', ip)
            list = dst_ports[ip].values()
            print('Packet number:', ', '.join(map(str,list)))
def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon
	separated string"""
    s = ""
    for i in range(6) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s += mac_addr[i*2:i*2+2].decode('utf-8')
        if i != 5:
          s += ":"
    		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return s

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    dict = {
        "192.168.0.100":b'7cd1c3949eb8',
        "192.168.0.103":b'd8969501a5c9',
        "192.168.0.1":b'f81a67cd576e'
    }
    i = 0
    for timestamp, buf in pcap:
        t = i
        i += 1
        # Print out the timestamp in UTC
	
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        arp = eth.data
        if not isinstance(arp, dpkt.arp.ARP):
            continue
        try:	
            arp = eth.arp
            if arp.op==2 :
               source_protocol_address = str(socket.inet_ntoa(arp.spa))
               source_hardware_address = binascii.hexlify(arp.sha)
               if source_protocol_address not in dict:
                  continue
               if dict[source_protocol_address] != source_hardware_address:
                  print("ARP spoofing!")
                  print("Src MAC:",add_colons_to_mac(binascii.hexlify(arp.sha)))
                  print("Dst MAC:",add_colons_to_mac(binascii.hexlify(arp.tha)))
                  print("Packet number:",t)
        except Exception:
            traceback.print_exc()
def print_packets1(pcap):
    
    i = 0
    list = []
    for timestamp, buf in pcap:
        list.append([timestamp, dpkt.ethernet.Ethernet(buf)])

        # Print out the timestamp in UTC
    for k in range(len(list)):
        timestamp, eth = list[k]
        if k == len(list) - 1:
           continue
        timestamp1, eth1 = list[k+1]
        list1 = []
        list1.append(eth)
        list1.append(eth1)
        k1 = k+1
        while(timestamp1 - timestamp < 1):
           k1 += 1
           if(k1 < len(list)):
              timestamp1, eth1 = list[k1]
              list1.append(eth1)
           else:
              break
        if(len(list1)<101):
           continue
        dict = {}
        dict1 = {}
        q = k
        for l in range(len(list1)):
           item = list1[l]  
        # Unpack the Ethernet frame (mac src/dst, ethertype)
           ip = item.data
           if not isinstance(ip, dpkt.ip.IP):
              q += 1
              continue
           
           dest_protocol_address = str(socket.inet_ntoa(ip.dst))
           if ip.p==dpkt.ip.IP_PROTO_TCP:
              tcp = ip.data
              if tcp.flags & dpkt.tcp.TH_SYN:
                 temp = dest_protocol_address + str(':') + str(tcp.dport)
                 if temp in dict:
                    dict[temp] += 1
                    dict1[temp].append(q)
                 else:
                    dict[temp] = 1
                    dict1[temp] = [q]
                 if 101 in dict.values():
                    keys = getList(dict)  
                    values = getListV(dict)  
                    index = values.index(101)  
                    Key = keys[index]
                    str1 = ', '.join(map(str, dict1[Key]))
                    Key = Key.split(':')
                    print("SYN floods!")
                    print("Dst IP:", Key[0])
                    print("Dst Port:", Key[1])
                    print("Packet number:", str1)
                    return
           q += 1
        #   except Exception as e:
         #     print("An exception occurred", e)
def getList(dict):
    list = []
    for key in dict.keys():
        list.append(key)
         
    return list
def getListV(dict):
    list = []
    for key in dict.values():
        list.append(key)
         
    return list
def test(filename):
    """Open up a test pcap file and print out the packets"""
    
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)
        f.close()
    portscan(filename)
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets1(pcap)
        f.close()
   # portscan(filename)
if __name__ == '__main__':
    test(sys.argv[1])

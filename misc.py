from  __future__ import print_function

class DHCP(object):

    hw_addr = '0a:e4:1c:d1:3e:44'
    dhcp_server = '192.168.1.1'
    netmask = '255.255.255.0'
    dns = '8.8.8.8'
    bin_dns = addrconv.ipv4.text_to_bin(dns)
    hostname = 'huehuehue'
    bin_netmask = addrconv.ipv4.text_to_bin(netmask)
    bin_server = addrconv.ipv4.text_to_bin(dhcp_server)
    pool = ['192.168.1.'+ str(x) for x in range(3,254)]
    leases = {}
    offers = {}
    lease_time = 60 * 60

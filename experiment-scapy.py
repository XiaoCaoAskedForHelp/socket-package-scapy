from scapy.all import sniff, IP, TCP, UDP, ICMP
from tkinter import *
import threading

# 全局变量用于控制捕获是否继续
capture_flag = False
capture_thread = None


def packet_handler(packet):
    global capture_flag
    if capture_flag:
        if IP in packet:
            ip_packet = packet[IP]

            # 分析是UDP还是TCP报文
            if UDP in ip_packet:
                protocol = "UDP"
            elif TCP in ip_packet:
                protocol = "TCP"
            else:
                protocol = "Unknown"

            # 分析源和目标IP地址
            source_ip = ip_packet.src
            dest_ip = ip_packet.dst

            # 分析源和目标端口号
            if protocol == "UDP":
                udp_packet = ip_packet[UDP]
                source_port = udp_packet.sport
                dest_port = udp_packet.dport
            elif protocol == "TCP":
                tcp_packet = ip_packet[TCP]
                source_port = tcp_packet.sport
                dest_port = tcp_packet.dport
            else:
                source_port = "N/A"
                dest_port = "N/A"

            # 分析IP数据报的总长度、标识、片偏移量和生存时间
            total_length = ip_packet.len
            identification = ip_packet.id
            fragment_offset = ip_packet.frag
            ttl = ip_packet.ttl

            # 在这里将信息显示在Text窗口中，或者根据需要进行其他操作
            print(f"Protocol: {protocol}")
            print(f"Source IP: {source_ip}, Destination IP: {dest_ip}")
            print(f"Source Port: {source_port}, Destination Port: {dest_port}")
            print(f"Total Length: {total_length}, Identification: {identification}")
            print(f"Fragment Offset: {fragment_offset}, TTL: {ttl}")
            print("-" * 50)

            txt1.insert(END, f"Protocol: {protocol}\n"
                        + f"Source IP: {source_ip}, Destination IP: {dest_ip}\n"
                        + f"Source Port: {source_port}, Destination Port: {dest_port}\n"
                        + f"Total Length: {total_length}, Identification: {identification}\n"
                        + f"Fragment Offset: {fragment_offset}, TTL: {ttl}\n"
                        + "-" * 50 + '\n')
            txt1.see(END)


# 设置要抓包的网络接口
network_interface = "ens33"


def run_capture():
    print("start")
    # 开始捕获数据包，可根据需要过滤特定协议或端口
    sniff(iface=network_interface, prn=packet_handler)


def start_capture():
    global capture_flag, capture_thread
    if not capture_flag:
        capture_flag = True
        capture_thread = threading.Thread(target=run_capture)
        capture_thread.start()


def stop_capture():
    global capture_flag, capture_thread
    if capture_flag:
        capture_flag = False


root = Tk()
root.title(f'获取TCP/UDP报文')
root.geometry('500x800')

lb1 = Label(root, text='报文', font=10)
txt1 = Text(root, height=40)
lb1.pack()
txt1.pack()

start_btn = Button(root, text='开始获取',
                   bg='#d3fbfb',
                   fg='green',
                   font=('华文新魏', 20),
                   command=start_capture)

pause_btn = Button(root, text='停止获取',
                   fg='green',
                   font=('华文新魏', 20),
                   command=stop_capture)

start_btn.pack()
pause_btn.pack()
root.mainloop()

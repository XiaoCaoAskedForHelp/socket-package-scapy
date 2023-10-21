import socket
import struct
from tkinter import *
import threading

# 全局变量用于控制捕获是否继续
capture_flag = False
capture_thread = None


def getsocket():
    # 创建原始套接字，需要管理员或root权限
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # 设置网络接口为混杂模式
    interface = "ens33"  # 你需要替换为实际的网络接口名称
    raw_socket.bind((interface, 0))
    return raw_socket


def packet_handler():
    try:
        while (True):
            global capture_flag
            if capture_flag:
                # 接收报文
                packet, _ = raw_socket.recvfrom(65535)

                # 使用struct.unpack()函数解析IP头部的各个字段，包括版本、头部长度、TTL、协议类型、源IP地址和目标IP地址等。
                # 格式字符串，它定义了如何解析二进制数据。每个字符代表一个特定的数据类型和大小
                # '!' 表示使用网络字节顺序（big-endian），这是IP头部中通常使用的字节顺序。
                # 'B' 表示一个无符号字节（8位）。
                # 'H' 表示一个无符号短整数（16位）。
                # '4s' 表示一个4字节的字符串。

                # 解析以太网头部，前14个字节
                eth_header = struct.unpack('!6s6sH', packet[:14])
                destination_mac = ':'.join(['%02x' % b for b in eth_header[0]])
                source_mac = ':'.join(['%02x' % b for b in eth_header[1]])
                ether_type = eth_header[2]

                # 如果以太网类型是IPv4
                if ether_type == 0x0800:
                    # 解析IP头部，下一个字节
                    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
                    version_and_ihl = ip_header[0]
                    version = version_and_ihl >> 4
                    ihl = (version_and_ihl & 0x0F) * 4
                    ttl = ip_header[5]
                    protocol = ip_header[6]
                    source_ip = socket.inet_ntoa(ip_header[8])
                    dest_ip = socket.inet_ntoa(ip_header[9])
                    total_length = ip_header[2]
                    identification = ip_header[3]
                    fragment_offset = ip_header[4]

                    # 打印IP数据报的总长度、标识、片偏移量、生存时间等信息
                    print(
                        f"Total Length: {total_length}, Identification: {identification}, Fragment Offset: {fragment_offset}, TTL: {ttl}")

                    # 如果协议是TCP或UDP
                    if protocol == 6:  # TCP
                        tcp_header = struct.unpack('!HHLLBBHHH', packet[ihl:ihl + 20])
                        source_port = tcp_header[0]
                        dest_port = tcp_header[1]
                        print(
                            f"TCP Packet - Source IP: {source_ip}, Destination IP: {dest_ip}, Source Port: {source_port}, Destination Port: {dest_port}")
                        txt1.insert(END, f"TCP Packet:\n"
                                    + f"Source IP: {source_ip}, Destination IP: {dest_ip}\n"
                                    + f"Source Port: {source_port}, Destination Port: {dest_port}\n"
                                    + f"Identification: {identification}, Fragment Offset: {fragment_offset}\n"
                                    + f"Total Length: {total_length}, TTL: {ttl}\n"
                                    + "-" * 50 + "\n")
                        txt1.see(END)  # 滚动以显示最新内容
                    elif protocol == 17:  # UDP
                        udp_header = struct.unpack('!HHHH', packet[ihl:ihl + 8])
                        source_port = udp_header[0]
                        dest_port = udp_header[1]
                        print(
                            f"UDP Packet - Source IP: {source_ip}, Destination IP: {dest_ip}, Source Port: {source_port}, Destination Port: {dest_port}")
                        txt2.insert(END, f"UDP Packet:\n"
                                    + f"Source IP: {source_ip}, Destination IP: {dest_ip}\n"
                                    + f"Source Port: {source_port}, Destination Port: {dest_port}\n"
                                    + f"Identification: {identification}, Fragment Offset: {fragment_offset}\n"
                                    + f"Total Length: {total_length}, TTL: {ttl}\n"
                                    + "-" * 50 + "\n")
                        txt2.see(END)  # 滚动以显示最新内容

    except KeyboardInterrupt:
        print("捕获操作被中断")
        raw_socket.close()


def start_capture():
    global capture_flag, capture_thread
    if not capture_flag:
        capture_flag = True
        capture_thread = threading.Thread(target=packet_handler)
        capture_thread.start()


def stop_capture():
    global capture_flag, capture_thread
    if capture_flag:
        capture_flag = False


if __name__ == "__main__":
    print("starting")

    raw_socket = getsocket()
    root = Tk()

    root.title(r'获取TCP\UDP报文')
    # 进入消息循环
    root.geometry('600x800')
    start_btn = Button(root, text='开始获取',
                       bg='#d3fbfb',
                       fg='green',
                       font=('华文新魏', 20),
                       command=start_capture)

    pause_btn = Button(root, text='停止获取',
                       fg='green',
                       font=('华文新魏', 20),
                       command=stop_capture)

    lb1 = Label(root, text='TCP报文', font=10)
    txt1 = Text(root, height=18, )
    lb2 = Label(root, text='UDP报文', font=10)
    txt2 = Text(root, height=18)

    start_btn.pack()
    pause_btn.pack()
    lb1.pack()
    txt1.pack()
    lb2.pack()
    txt2.pack()

    root.mainloop()

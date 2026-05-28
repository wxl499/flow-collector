# flow-collector
DPDK collects traffic and transmits it to the Java program via UDP socket. The Java program inserts the data into the ClickHouse database

# 环境版本要求
`dpdk-stable-25.11.2`

`JDK 11`

`ClickHouse server version 26.5.1.882`

# C程序输出展示
```c
Sent flow record: 59 bytes, packets: 13, bytes: 692

=== 发送流记录到Java程序 ===
源MAC地址: 00:0c:29:fe:6d:b2
目的MAC地址: 00:90:27:f9:85:e7
源IP地址: 241.104.168.192
目的IP地址: 40.104.168.192
源端口: 30832
目的端口: 60864
协议: 6 (TCP)
VLAN ID: 0
流开始时间: 1854039033430656 ns
流结束时间: 1854039033430656 ns
持续时间: 0 ns
包数量: 1
字节数: 52
===========================
```

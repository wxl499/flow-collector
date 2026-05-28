#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>
#include <rte_ring.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 512
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_FLOWS 65536
#define ACTIVE_TIMEOUT_NS (30ULL * 1000000000ULL) // 30秒活跃超时
#define SCAN_INTERVAL_NS (1ULL * 1000000000ULL)   // 每1秒扫描一次超时流

// 流的唯一标识（五元组 + VLAN）
struct flow_key {
    uint8_t  src_mac[6];     // 源MAC地址
    uint8_t  dst_mac[6];     // 目的MAC地址
    uint32_t src_ip;        // 源地址
    uint32_t dst_ip;        // 目的地址
    uint16_t src_port;      // 源端口
    uint16_t dst_port;      // 目的端口
    uint8_t  proto;         // IP 协议号 (TCP=6, UDP=17...)
    uint16_t vlan_id;       // 0 表示无 VLAN
} __attribute__((packed));

// 流的统计信息
struct flow_record {
    struct flow_key key;          // 流标识

    uint64_t flow_start_time_ns;  // 首包到达时间（纳秒 Unix 时间戳）
    uint64_t flow_end_time_ns;    // 末包到达时间
    uint64_t packets;             // 总包数
    uint64_t bytes;               // 总字节数（IP 层 payload + 头，建议用 L3 总长）
};

// 全局变量
static struct rte_mempool *mbuf_pool;
static int udp_sock = -1;
static struct sockaddr_in java_addr;

// 哈希表定义
struct flow_entry {
    struct flow_record record;
    int active;
    uint64_t last_seen; // 最后一次看到该流的时间
};

static struct flow_entry flow_table[MAX_FLOWS];

static int g_java_sockfd = -1;  // 全局 socket 句柄

// 初始化UDP socket
static int init_udp_socket(const char *ip, int port) {
    g_java_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_java_sockfd < 0) {
        perror("Failed to create UDP socket");
        return -1;
    }
    
    memset(&java_addr, 0, sizeof(java_addr));
    java_addr.sin_family = AF_INET;
    java_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &java_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid Java server IP address: %s\n", ip);
        close(g_java_sockfd);
        return -1;
    }
    
    printf("UDP socket initialized to send to %s:%d\n", ip, port);
    return 0;
}

// 发送流记录到Java程序
static void send_flow_to_java(const struct flow_record *record) {
    if (g_java_sockfd < 0) {
        fprintf(stderr, "UDP socket not initialized\n");
        return;
    }
    
    // 打印详细的流记录信息（用于调试）
    printf("\n=== 发送流记录到Java程序 ===\n");
    printf("源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
           record->key.src_mac[0], record->key.src_mac[1], record->key.src_mac[2],
           record->key.src_mac[3], record->key.src_mac[4], record->key.src_mac[5]);
    printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
           record->key.dst_mac[0], record->key.dst_mac[1], record->key.dst_mac[2],
           record->key.dst_mac[3], record->key.dst_mac[4], record->key.dst_mac[5]);
    printf("源IP地址: %u.%u.%u.%u\n",
           (record->key.src_ip >> 0) & 0xFF,
           (record->key.src_ip >> 8) & 0xFF,
           (record->key.src_ip >> 16) & 0xFF,
           (record->key.src_ip >> 24) & 0xFF);
    printf("目的IP地址: %u.%u.%u.%u\n",
           (record->key.dst_ip >> 0) & 0xFF,
           (record->key.dst_ip >> 8) & 0xFF,
           (record->key.dst_ip >> 16) & 0xFF,
           (record->key.dst_ip >> 24) & 0xFF);
    printf("源端口: %u\n", record->key.src_port);
    printf("目的端口: %u\n", record->key.dst_port);
    printf("协议: %u ", record->key.proto);
    switch(record->key.proto) {
        case IPPROTO_TCP:
            printf("(TCP)\n");
            break;
        case IPPROTO_UDP:
            printf("(UDP)\n");
            break;
        case IPPROTO_ICMP:
            printf("(ICMP)\n");
            break;
        default:
            printf("(其他)\n");
            break;
    }
    printf("VLAN ID: %u\n", record->key.vlan_id);
    printf("流开始时间: %" PRIu64 " ns\n", record->flow_start_time_ns);
    printf("流结束时间: %" PRIu64 " ns\n", record->flow_end_time_ns);
    printf("持续时间: %" PRIu64 " ns\n", record->flow_end_time_ns - record->flow_start_time_ns);
    printf("包数量: %" PRIu64 "\n", record->packets);
    printf("字节数: %" PRIu64 "\n", record->bytes);
    printf("===========================\n\n");

    // 序列化流记录
    uint8_t buffer[1024];
    size_t offset = 0;
    
    // 写入flow_key (共27字节)
    memcpy(buffer + offset, &record->key, sizeof(struct flow_key));
    offset += sizeof(struct flow_key);
    
    // 写入其他字段
    memcpy(buffer + offset, &record->flow_start_time_ns, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(buffer + offset, &record->flow_end_time_ns, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(buffer + offset, &record->packets, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(buffer + offset, &record->bytes, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    // 发送数据
    ssize_t sent = sendto(g_java_sockfd, buffer, offset, 0, 
                         (struct sockaddr*)&java_addr, sizeof(java_addr));
    
    if (sent != (ssize_t)offset) {
        perror("Failed to send flow record to Java");
    } else {
        printf("Sent flow record: %d bytes, packets: %lu, bytes: %lu\n", 
               (int)sent, record->packets, record->bytes);
    }
}

// 结束并发送流记录
static void end_and_send_flow(int index, uint64_t current_time) {
    if (!flow_table[index].active) {
        return;
    }
    
    // 更新流结束时间
    flow_table[index].record.flow_end_time_ns = current_time;
    
    // 发送流记录到Java程序
    send_flow_to_java(&flow_table[index].record);
    
    // 清理该流记录
    memset(&flow_table[index], 0, sizeof(struct flow_entry));
}

// 计算哈希值
static inline uint32_t calculate_flow_hash(const struct flow_key *key) {
    return rte_jhash(key, sizeof(struct flow_key), 0) % MAX_FLOWS;
}

// 比较两个flow_key是否相等
static inline int compare_flow_keys(const struct flow_key *a, const struct flow_key *b) {
    return memcmp(a, b, sizeof(struct flow_key)) == 0;
}

// 查找或创建流记录
static struct flow_record* get_or_create_flow_record(const struct flow_key *key, uint64_t timestamp) {
    uint32_t hash = calculate_flow_hash(key);
    uint32_t original_hash = hash;
    
    do {
        if (!flow_table[hash].active) {
            // 创建新的流记录
            memset(&flow_table[hash].record, 0, sizeof(struct flow_record));
            flow_table[hash].record.key = *key;
            flow_table[hash].record.flow_start_time_ns = timestamp;
            flow_table[hash].record.flow_end_time_ns = timestamp;
            flow_table[hash].record.packets = 1;
            flow_table[hash].record.bytes = 0; // 初始为0，后面会累加
            flow_table[hash].last_seen = timestamp;
            flow_table[hash].active = 1;
            return &flow_table[hash].record;
        }
        
        if (compare_flow_keys(&flow_table[hash].record.key, key)) {
            // 更新现有流记录
            flow_table[hash].record.flow_end_time_ns = timestamp;
            flow_table[hash].record.packets++;
            flow_table[hash].last_seen = timestamp;
            return &flow_table[hash].record;
        }
        
        hash = (hash + 1) % MAX_FLOWS;
    } while (hash != original_hash);
    
    return NULL; // 哈希表已满
}

// 获取VLAN ID
static inline uint16_t get_vlan_id(struct rte_ether_hdr *eth_hdr) {
    struct rte_vlan_hdr *vlan_hdr;
    
    if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
        vlan_hdr = (struct rte_vlan_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
        return rte_be_to_cpu_16(vlan_hdr->vlan_tci) & 0x0FFF;
    }
    return 0; // 无VLAN
}

// 检查TCP包是否包含FIN或RST标志
static inline int is_tcp_fin_rst(struct rte_tcp_hdr *tcp_hdr) {
    return (tcp_hdr->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != 0;
}

// 解析IPv4包
static void parse_ipv4_packet(struct rte_mbuf *pkt, uint64_t timestamp) {
    struct rte_ether_hdr *eth_hdr;   // 以太网头部指针
    struct rte_ipv4_hdr *ipv4_hdr;   // IPv4 头部指针
    struct rte_tcp_hdr *tcp_hdr;     // TCP 头部指针
    struct rte_udp_hdr *udp_hdr;     // UDP 头部指针
    struct flow_key key;             // 用来唯一标识一条“网络流”
    struct flow_record *flow_rec;    // 指向该流的统计记录
    int should_end_flow = 0;
    
    // 获取以太网头部
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    // 复制MAC地址
    memcpy(key.src_mac, eth_hdr->src_addr.addr_bytes, 6);
    memcpy(key.dst_mac, eth_hdr->dst_addr.addr_bytes, 6);
    // printf("Parsing packet: src MAC %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
    //        ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ", "
    //        "dst MAC %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
    //        ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
    //        eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
    //        eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
    //        eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5],
    //        eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
    //        eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
    //        eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);

    // 跳过以太网头部，获取IP头
    if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
        // 如果有VLAN标签，需要跳过VLAN头
        struct rte_vlan_hdr *vlan_hdr = (struct rte_vlan_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
        ipv4_hdr = (struct rte_ipv4_hdr *)((char *)vlan_hdr + sizeof(struct rte_vlan_hdr));
    } else {
        ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    }
    // uint32_t ipv4_src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    // uint32_t ipv4_dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    // printf("  IPv4: src IP %u.%u.%u.%u, dst IP %u.%u.%u.%u, proto %u\n",
    //         (ipv4_src_addr >> 24) & 0xFF, (ipv4_src_addr >> 16) & 0xFF,
    //         (ipv4_src_addr >> 8) & 0xFF, ipv4_src_addr & 0xFF,
    //         (ipv4_dst_addr >> 24) & 0xFF, (ipv4_dst_addr >> 16) & 0xFF,
    //         (ipv4_dst_addr >> 8) & 0xFF, ipv4_dst_addr & 0xFF,
    //         ipv4_hdr->next_proto_id);
    
    // 检查是否为IPv4
    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type) || 
        (ipv4_hdr->version_ihl >> 4) == 4) {
        
        // 填充流键值
        key.src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
        key.dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
        key.proto = ipv4_hdr->next_proto_id;
        key.vlan_id = get_vlan_id(eth_hdr);
        // printf("  Flow: src IP %u.%u.%u.%u, dst IP %u.%u.%u.%u, proto %u, vlan %u\n",
        //        (key.src_ip >> 24) & 0xFF, (key.src_ip >> 16) & 0xFF,
        //        (key.src_ip >> 8) & 0xFF, key.src_ip & 0xFF,
        //        (key.dst_ip >> 24) & 0xFF, (key.dst_ip >> 16) & 0xFF,
        //        (key.dst_ip >> 8) & 0xFF, key.dst_ip & 0xFF,
        //        key.proto, key.vlan_id);

        // 根据协议类型设置端口号
        switch (key.proto) {
            case IPPROTO_TCP:
                tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + 
                    (ipv4_hdr->version_ihl & 0xF) * 4);
                key.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                key.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                // 检查TCP FIN/RST标志
                if (is_tcp_fin_rst(tcp_hdr)) {
                    should_end_flow = 1;
                }
                // printf("Timestamp: %" PRIu64 "\n", timestamp);
                break;
                
            case IPPROTO_UDP:
                udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + 
                    (ipv4_hdr->version_ihl & 0xF) * 4);
                key.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                key.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                // printf("Timestamp: %" PRIu64 "\n", timestamp);
                break;
                
            default:
                key.src_port = 0;
                key.dst_port = 0;
                break;
        }
        
        // 获取或创建流记录
        flow_rec = get_or_create_flow_record(&key, timestamp);
        if (flow_rec != NULL) {
            // 累加字节数（IP层总长度）
            flow_rec->bytes += rte_be_to_cpu_16(ipv4_hdr->total_length);
            
            // 如果是TCP FIN/RST包，则立即结束流
            if (should_end_flow && key.proto == IPPROTO_TCP) {
                // 找到对应的正向或反向流并结束它
                for (int i = 0; i < MAX_FLOWS; i++) {
                    if (flow_table[i].active && 
                        compare_flow_keys(&flow_table[i].record.key, &key)) {
                        end_and_send_flow(i, timestamp);
                        break;
                    }
                }
            }
        }
    }
}

// 输出并清理超时的流记录
static void cleanup_expired_flows(uint64_t current_time) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (flow_table[i].active && 
            (current_time - flow_table[i].last_seen > ACTIVE_TIMEOUT_NS)) {
            
            // 发送流记录到Java程序
            end_and_send_flow(i, current_time);
        }
    }
}

// 主处理循环
static void main_loop(void) {
    struct rte_mbuf *pkts_burst[BURST_SIZE];    // 存放一批数据包的指针数组
    unsigned nb_rx;                             // 实际收到的包数
    uint64_t prev_tsc = 0;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * 1000000; // 1秒，CPU 硬件时钟，速度极快，适合高性能程序做定时

    printf("Main loop started\n");

    while (1) {
        // 获取当前时间戳
        const uint64_t cur_tsc = rte_rdtsc();
        
        // 每隔一段时间输出统计数据
        if (unlikely(prev_tsc == 0))
            prev_tsc = cur_tsc;
        
        // 检查是否需要清理超时的流记录,超时的流记录会被发送到Java程序
        if (cur_tsc - prev_tsc > drain_tsc) {
            cleanup_expired_flows(cur_tsc);
            prev_tsc = cur_tsc;
        }
        
        // 从所有端口接收数据包
        for (uint16_t portid = 0; portid < rte_eth_dev_count_avail(); portid++) {
            nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, BURST_SIZE);
            
            if (unlikely(nb_rx == 0))
                continue;
                
            // 处理接收到的数据包
            for (unsigned i = 0; i < nb_rx; i++) {
                parse_ipv4_packet(pkts_burst[i], rte_rdtsc());
                rte_pktmbuf_free(pkts_burst[i]);
            }
        }
    }
}

// 打印网卡端口支持的RSS能力信息
void print_port_capabilities(uint16_t portid) {
    struct rte_eth_dev_info dev_info = {0};
    int ret;

    // 调用 API 获取设备信息
    ret = rte_eth_dev_info_get(portid, &dev_info);
    if (ret != 0) {
        printf("Failed to get device info for port %u: %s\n", portid, rte_strerror(-ret));
        return;
    }

    // 打印关键信息
    printf("=== Port %u Capabilities ===\n", portid);
    printf("Driver: %s\n", dev_info.driver_name);
    printf("Max RX queues: %u\n", dev_info.max_rx_queues);
    printf("Max TX queues: %u\n", dev_info.max_tx_queues);

    // 👇 这就是您要的：支持的 RSS 类型掩码
    printf("Supported RSS hash functions (rss_offloads): 0x%lx\n", dev_info.flow_type_rss_offloads);

    // 可选：解析具体支持哪些协议
    uint64_t rss = dev_info.flow_type_rss_offloads;
    if (rss & RTE_ETH_RSS_IPV4)                     //I211网卡支持的选项
        printf("  - IPv4\n");
    if (rss & RTE_ETH_RSS_FRAG_IPV4)
        printf("  - Fragmented IPv4\n");
    if (rss & RTE_ETH_RSS_NONFRAG_IPV4_TCP)         //I211网卡支持的选项
        printf("  - TCP over IPv4\n");              
    if (rss & RTE_ETH_RSS_NONFRAG_IPV4_UDP)         //I211网卡支持的选项
        printf("  - UDP over IPv4\n");
    if (rss & RTE_ETH_RSS_IPV6)
        printf("  - IPv6\n");
    if (rss & RTE_ETH_RSS_FRAG_IPV6)
        printf("  - Fragmented IPv6\n");
    if (rss & RTE_ETH_RSS_NONFRAG_IPV6_TCP)
        printf("  - TCP over IPv6\n");
    if (rss & RTE_ETH_RSS_NONFRAG_IPV6_UDP)
        printf("  - UDP over IPv6\n");
    if (rss & RTE_ETH_RSS_SCTP)
        printf("  - SCTP\n");
    if (rss & RTE_ETH_RSS_TUNNEL)
        printf("  - Tunnel (VXLAN, GRE, etc.)\n");
    // ... 其他类型可继续添加

    printf("============================\n\n");
}

// 初始化端口
static int init_port(uint16_t portid) {

    print_port_capabilities(portid);
    
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP,
            },
        },
    };
    
    const uint16_t rx_rings = 1, tx_rings = 0;
    int retval;
    uint16_t q;
    
    printf("Initializing port %u...\n", portid);
    
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(portid, rx_rings, tx_rings, &port_conf);
    if (retval != 0){
        return retval;
    }
        

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(portid, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(portid), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    // /* Allocate and set up 1 TX queue per Ethernet port. */
    // for (q = 0; q < tx_rings; q++) {
    //     retval = rte_eth_tx_queue_setup(portid, q, TX_RING_SIZE,
    //             rte_eth_dev_socket_id(portid), NULL);
    //     if (retval < 0)
    //         return retval;
    // }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(portid);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(portid, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
           portid,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(portid);

    return 0;
}

// 主函数
int main(int argc, char *argv[]) {
    int ret;
    uint16_t portid;
    
    // 初始化EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    // 创建mbuf池
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * 2,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    
    if (mbuf_pool == NULL)
        rte_panic("Cannot create mbuf pool\n");

    // 初始化UDP socket
    if (init_udp_socket("192.168.198.180", 9999) != 0) {
        rte_panic("Cannot initialize UDP socket\n");
    }

    // 初始化所有端口
    RTE_ETH_FOREACH_DEV(portid) {
        if (init_port(portid) != 0)
            rte_panic("Cannot init port %"PRIu16"\n", portid);
    }

    printf("DPDK Flow Collector running...\n");
    
    // 启动主循环
    main_loop();

    // 清理资源
    if (udp_sock >= 0) {
        close(udp_sock);
    }
    
    return 0;
}
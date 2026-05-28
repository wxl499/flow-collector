-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS network_analytics;

-- 使用数据库
USE network_analytics;

-- 创建流统计表
CREATE TABLE IF NOT EXISTS flow_statistics (
src_mac String,                              -- 源MAC地址
dst_mac String,                              -- 目的MAC地址
src_ip UInt32,                               -- 源IP地址
dst_ip UInt32,                               -- 目的IP地址
src_port UInt16,                             -- 源端口
dst_port UInt16,                             -- 目的端口
protocol UInt8,                              -- 协议号 (TCP=6, UDP=17)
vlan_id UInt16,                              -- VLAN ID (0表示无VLAN)

                                               flow_start_time DateTime64(3),               -- 流开始时间 (毫秒精度)
                                               flow_end_time DateTime64(3),                 -- 流结束时间 (毫秒精度)
                                               duration_ms Float64 MATERIALIZED (toUnixTimestamp64Milli(flow_end_time) - toUnixTimestamp64Milli(flow_start_time))/1000, -- 持续时间(秒)

                                               packets UInt64,                              -- 包数量
                                               bytes UInt64,                                -- 字节数

                                               src_ip_str String MATERIALIZED IPv4NumToString(src_ip),  -- 源IP地址字符串形式
                                               dst_ip_str String MATERIALIZED IPv4NumToString(dst_ip),  -- 目的IP地址字符串形式

                                               created_at DateTime DEFAULT now()             -- 记录创建时间
) ENGINE = MergeTree()
ORDER BY (flow_start_time, src_ip, dst_ip, src_port, dst_port)
PARTITION BY toYYYYMM(flow_start_time)
SETTINGS index_granularity = 8192;

-- 创建物化视图用于聚合统计
CREATE MATERIALIZED VIEW IF NOT EXISTS flow_aggregates_minute
ENGINE = SummingMergeTree()
ORDER BY (toDate(flow_start_time), toStartOfMinute(flow_start_time), src_ip, dst_ip, protocol)
AS SELECT
toDate(flow_start_time) AS date,
toStartOfMinute(flow_start_time) AS minute,
src_ip,
dst_ip,
protocol,
sum(packets) AS total_packets,
sum(bytes) AS total_bytes,
count() AS flow_count
FROM flow_statistics
GROUP BY date, minute, src_ip, dst_ip, protocol;

-- 创建索引
ALTER TABLE flow_statistics ADD INDEX idx_src_dst_ip (src_ip, dst_ip) TYPE bloom_filter() GRANULARITY 1;
ALTER TABLE flow_statistics ADD INDEX idx_protocol (protocol) TYPE minmax GRANULARITY 3;
ALTER TABLE flow_statistics ADD INDEX idx_port (src_port, dst_port) TYPE set(1000) GRANULARITY 4;
ALTER TABLE flow_statistics ADD INDEX idx_mac (src_mac, dst_mac) TYPE set(1000) GRANULARITY 4;
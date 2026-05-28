package cn.srsw;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.*;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FlowReceiver {

    private static final Logger LOGGER = Logger.getLogger(FlowReceiver.class.getName());

    // 流的唯一标识（五元组 + VLAN + MAC地址）
    public static class FlowKey {
        public byte[] srcMac;      // 源MAC地址
        public byte[] dstMac;      // 目的MAC地址
        public long srcIp;         // 源地址
        public long dstIp;         // 目的地址
        public int srcPort;        // 源端口
        public int dstPort;        // 目的端口
        public byte proto;         // IP 协议号 (TCP=6, UDP=17...)
        public int vlanId;         // 0 表示无 VLAN

        public FlowKey(byte[] srcMac, byte[] dstMac, long srcIp, long dstIp,
                       int srcPort, int dstPort, byte proto, int vlanId) {
            this.srcMac = srcMac.clone();
            this.dstMac = dstMac.clone();
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.proto = proto;
            this.vlanId = vlanId;
        }

        public String getSrcMacStr() {
            return formatMacAddress(srcMac);
        }

        public String getDstMacStr() {
            return formatMacAddress(dstMac);
        }

        private String formatMacAddress(byte[] mac) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02x", mac[i] & 0xFF));
                if (i < mac.length - 1) {
                    sb.append(":");
                }
            }
            return sb.toString();
        }

        @Override
        public String toString() {
            return String.format("FlowKey{srcMac=%s, dstMac=%s, srcIp=%s, dstIp=%s, srcPort=%d, dstPort=%d, proto=%d, vlanId=%d}",
                    getSrcMacStr(), getDstMacStr(), formatIpAddress(srcIp), formatIpAddress(dstIp), srcPort, dstPort, proto, vlanId);
        }

        private String formatIpAddress(long ip) {
            return String.format("%d.%d.%d.%d",
                    (ip >> 24) & 0xFF,
                    (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF,
                    ip & 0xFF);
        }
    }

    // 流的统计信息
    public static class FlowRecord {
        public FlowKey key;                // 流标识
        public long flowStartTimeNs;      // 首包到达时间（纳秒 Unix 时间戳）
        public long flowEndTimeNs;        // 末包到达时间
        public long packets;              // 总包数
        public long bytes;                // 总字节数

        public FlowRecord(FlowKey key, long flowStartTimeNs, long flowEndTimeNs,
                          long packets, long bytes) {
            this.key = key;
            this.flowStartTimeNs = flowStartTimeNs;
            this.flowEndTimeNs = flowEndTimeNs;
            this.packets = packets;
            this.bytes = bytes;
        }

        @Override
        public String toString() {
            return String.format("FlowRecord{key=%s, startTime=%d, endTime=%d, duration=%d ns, packets=%d, bytes=%d}",
                    key, flowStartTimeNs, flowEndTimeNs, flowEndTimeNs - flowStartTimeNs, packets, bytes);
        }
    }

    private static final int PORT = 9999;
    private static final String CLICKHOUSE_URL = "jdbc:clickhouse:http://192.168.104.99:8123/network_analytics";
    private static final String CLICKHOUSE_USER = "default";
    private static final String CLICKHOUSE_PASSWORD = "";

    // 使用有界队列避免内存溢出，并设置合理的容量
    private BlockingQueue<FlowRecord> flowQueue = new LinkedBlockingQueue<>(10000);
    private AtomicBoolean running = new AtomicBoolean(true);

    public static void main(String[] args) {
        FlowReceiver receiver = new FlowReceiver();
        receiver.start();
    }

    public void start() {
        LOGGER.info("Starting Flow Receiver...");

        // 启动UDP接收线程
        Thread udpThread = new Thread(this::receiveFlowsFromUDPSocket, "UDP-Receiver");
        udpThread.setDaemon(false);
        udpThread.start();

        // 启动数据库写入线程
        Thread dbThread = new Thread(this::writeToDatabase, "DB-Writer");
        dbThread.setDaemon(false);
        dbThread.start();

        // 添加关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOGGER.info("Shutting down Flow Receiver...");
            running.set(false);
            try {
                udpThread.join(5000); // 等待最多5秒
                dbThread.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.log(Level.WARNING, "Interrupted during shutdown", e);
            }
        }));
    }

    // 接收流数据的UDP Socket方法
    private void receiveFlowsFromUDPSocket() {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(PORT);
            LOGGER.info("UDP server listening on port " + PORT);

            byte[] buffer = new byte[1024]; // 足够容纳FlowRecord序列化后的数据

            while (running.get()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                // 解析接收到的数据
                FlowRecord record = deserializeFlowRecord(packet.getData(), packet.getLength());
                if (record != null) {
                    // 使用put()而不是offer()，这样在队列满时会阻塞而不是丢弃数据
                    try {
                        flowQueue.put(record);
                        LOGGER.fine("Successfully queued flow record: " + record);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        LOGGER.log(Level.WARNING, "Interrupted while queuing flow record", e);
                        break;
                    }

                    // 输出到控制台（调试用）
                    System.out.println("Received and queued: " + record);
                }
            }
        } catch (IOException e) {
            if (running.get()) {
                LOGGER.log(Level.SEVERE, "Error in UDP receiver", e);
            }
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    // 从字节数组反序列化FlowRecord
    private FlowRecord deserializeFlowRecord(byte[] data, int length) {
        if (length < 54) { // 至少需要54字节（FlowKey 27字节 + 时间戳等 27字节）
            LOGGER.warning("Invalid data length: " + length);
            return null;
        }

        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        try {
            // 解析FlowKey部分 (27字节)
            byte[] srcMac = new byte[6];
            byte[] dstMac = new byte[6];
            bb.get(srcMac);    // 6 bytes
            bb.get(dstMac);    // 6 bytes
            long srcIp = Integer.toUnsignedLong(bb.getInt());    // 4 bytes (unsigned)
            long dstIp = Integer.toUnsignedLong(bb.getInt());    // 4 bytes (unsigned)
            int srcPort = Short.toUnsignedInt(bb.getShort());   // 2 bytes
            int dstPort = Short.toUnsignedInt(bb.getShort());   // 2 bytes
            byte proto = bb.get();        // 1 byte
            int vlanId = Short.toUnsignedInt(bb.getShort()); // 2 bytes

            // 解析FlowRecord部分
            long flowStartTimeNs = bb.getLong();  // 8 bytes
            long flowEndTimeNs = bb.getLong();    // 8 bytes
            long packets = bb.getLong();          // 8 bytes
            long bytes = bb.getLong();            // 8 bytes

            FlowKey key = new FlowKey(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, proto, vlanId);
            return new FlowRecord(key, flowStartTimeNs, flowEndTimeNs, packets, bytes);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error deserializing flow record", e);
            return null;
        }
    }

    // 将流数据写入ClickHouse数据库
    private void writeToDatabase() {
        Connection conn = null;
        PreparedStatement stmt = null;

        try {
            // 正确初始化数据库连接和PreparedStatement
            conn = DriverManager.getConnection(CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD);

            // 测试连接
            Statement testStmt = conn.createStatement();
            ResultSet resultSet = testStmt.executeQuery("SELECT now()");
            if (resultSet.next()){
                System.out.println("Current time in ClickHouse: " + resultSet.getTimestamp(1));
            }
            testStmt.close();

            // 准备批量插入语句
            String sql = "INSERT INTO flow_statistics (" +
                    "src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id, " +
                    "flow_start_time, flow_end_time, packets, bytes) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

            stmt = conn.prepareStatement(sql); // 初始化PreparedStatement

            int batchSize = 0;
            final int BATCH_SIZE = 1000;

            while (running.get() || !flowQueue.isEmpty()) {
                // 使用poll()带超时，避免在running为false时无限等待
                FlowRecord record = flowQueue.poll(1, TimeUnit.SECONDS);
                if (record == null) {
                    continue;
                }

                stmt.setString(1, record.key.getSrcMacStr());   // 源MAC地址
                stmt.setString(2, record.key.getDstMacStr());   // 目的MAC地址
                stmt.setLong(3, record.key.srcIp);
                stmt.setLong(4, record.key.dstIp);
                stmt.setInt(5, record.key.srcPort);
                stmt.setInt(6, record.key.dstPort);
                stmt.setInt(7, record.key.proto & 0xFF);        // 转换为无符号
                stmt.setInt(8, record.key.vlanId);

                // 转换纳秒时间戳为DateTime64格式
                stmt.setTimestamp(9, new Timestamp(record.flowStartTimeNs / 1_000_000)); // 转换为毫秒
                stmt.setTimestamp(10, new Timestamp(record.flowEndTimeNs / 1_000_000)); // 转换为毫秒

                stmt.setLong(11, record.packets);
                stmt.setLong(12, record.bytes);

                // 添加到批处理
                stmt.addBatch();
                batchSize++;

                // 当达到批量大小时执行
                if (batchSize >= BATCH_SIZE) {
                    stmt.executeBatch();
                    conn.commit();
                    batchSize = 0;
                    LOGGER.info("Executed batch of " + BATCH_SIZE + " records");
                }
            }

            // 执行剩余的批处理
            if (batchSize > 0) {
                stmt.executeBatch();
                conn.commit();
                LOGGER.info("Executed final batch of " + batchSize + " records");
            }

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error writing to database", e);
            // 如果有数据库连接，尝试回滚
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException rollbackEx) {
                    LOGGER.log(Level.WARNING, "Error during rollback", rollbackEx);
                }
            }
        } finally {
            try {
                if (stmt != null) {
                    stmt.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                LOGGER.log(Level.WARNING, "Error closing database resources", e);
            }
        }
    }
}

#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 判断数据包长度,如果小于IP头部长度,则丢弃
    if (buf->len < sizeof(ip_hdr_t)) return;

    // 创建备份,便于发送ICMP错误报文
    buf_t copy_buf;
    buf_copy(&copy_buf, buf, buf->len);

    // 检查报头
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4) return;
    if (swap16(ip_hdr->total_len16) != buf->len) return;

    // 先把头部校验等保存起来,接着再置0
    // 然后调用checksum16函数计算校验和,最后再恢复
    uint16_t hdr_checksum16_backup = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    if (hdr_checksum16 != hdr_checksum16_backup) return;
    ip_hdr->hdr_checksum16 = hdr_checksum16_backup;

    // 对比目的IP地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;

    // 如果数据包长度大于IP头部长度,说明之前有填充,需要去掉
    if (buf->len > swap16(ip_hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    // 去除IP头部
    uint8_t protocol = ip_hdr->protocol;
    uint8_t *src_ip = ip_hdr->src_ip;
    buf_remove_header(buf, ip_hdr->hdr_len * 4);

    // 如果协议无法识别,则调用icmp_unreachable函数发送ICMP不可达报文
    int tag = net_in(buf, protocol, src_ip);
    if (tag == -1) {
        icmp_unreachable(&copy_buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // 填充IP数据报头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    // 填充IP数据报头部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 填充校验和字段为0,计算校验和,再填充回去
    ip_hdr->hdr_checksum16 = 0;
    uint16_t new_checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = new_checksum;

    // arp_out发送出去
    arp_out(buf, ip);

}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    //求出最大负载长度
    int max_load_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);

    // 如果超过最大负载长度,则分片发送
    int i;
    static int id = 0;
    for (i = 0; (i + 1) * max_load_len < buf->len; i++) {
        buf_t ip_buf;
        buf_init(&ip_buf, max_load_len);
        memcpy(ip_buf.data, buf->data + i * max_load_len, max_load_len);
        ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_len >> 3), 1);
    }

    // 如果没有超过最大负载长度,或者分片后的最后一个分片小于等于最大负载,统一直接发送
    buf_t ip_buf;
    buf_init(&ip_buf, buf->len - i * max_load_len);
    memcpy(ip_buf.data, buf->data + i * max_load_len, buf->len - i * max_load_len);
    ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_len >> 3), 0);
    id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
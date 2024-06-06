#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    //对txbuf进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写ARP包头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 修改ARP包头的操作为ARP_REQUEST,并填写目标IP
    arp_pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);

    // 发送ARP请求
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    //对txbuf进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写ARP包头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 修改ARP包头的操作为ARP_REPLY,并填写目标IP和MAC
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);

    // 发送ARP响应
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 首先判断数据长度,如果小于ARP头部长度,则直接丢弃
    if (buf->len < sizeof(arp_pkt_t))
    {
        return;
    }

    // 获取ARP包头,检查硬件类型、协议类型、硬件地址长度和协议地址长度是否正确
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    if (arp_pkt->hw_type16 != swap16(ARP_HW_ETHER) || arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP) || arp_pkt->hw_len != NET_MAC_LEN || arp_pkt->pro_len != NET_IP_LEN) return;
    if (arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY)) return;

    // 更新ARP表
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    //查看该报文的IP地址是否在arp_buf中
    buf_t *arp_buf_entry = (buf_t *) map_get(&arp_buf, arp_pkt->sender_ip);
    if (arp_buf_entry != NULL){
        //将该报文发送出去
        ethernet_out(arp_buf_entry, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    }
    else{
        if (arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0){
            // 如果是ARP请求且目标是本机IP,则回复ARP响应
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // 根据IP地址查找ARP表
    uint8_t *mac = map_get(&arp_table, ip);
    if (mac != NULL){
        // 如果找到,则直接发送
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    }
    else{
        // 如果没有找到,则先判断arp_buf中是否有该IP的报文
        buf_t *arp_buf_entry = (buf_t *) map_get(&arp_buf, ip);
        if (arp_buf_entry != NULL){
            //如果有,则说明其实正在等待回应ARP请求,此时不能再发送ARP请求
            return;
        }
        else{
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }

    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}
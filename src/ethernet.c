#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    // step1:判断数据包长度是否小于以太网包头长度,如果小于则丢弃
    if (buf->len < sizeof(ether_hdr_t)){
        return;
    }

    //step2:解析以太网包头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    net_protocol_t protocol = swap16(hdr->protocol16);
    uint8_t *src = hdr->src;
    buf_remove_header(buf, sizeof(ether_hdr_t));

    //step3:向上传递数据包
    net_in(buf, protocol, src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    // step1:判断数据长度，如果小于46字节则填充0
    if (buf->len < 46){
        buf_add_padding(buf, 46 - buf->len);
    }

    // step2:填充以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // step3:填充目标MAC地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);

    // step4:填充源MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);

    // step5:填充协议类型
    hdr->protocol16 = swap16(protocol);

    // step6:调用驱动发送数据包
    driver_send(buf);

}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}

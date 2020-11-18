#define _GNU_SOURCE

#include <arpa/inet.h>
#include <linux/ip.h>

#include "includes.h"
#include "checksum.h"
/******checksum.c******
*构造数据包原始套接字时会用到校验和的计算
*/
//计算数据包ip头中的校验和
uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{  //count为tcp_ip头部的header_length字段的值（*4）
    //header_length以4字节为单位
    //count也就是当前ip包的头部大小【https://www.thegeekstuff.com/2012/05/ip-header-checksum/】
    register unsigned long sum = 0;
    //注意checksum是ip头部的16个bit为单位相加，然后取反
    for (sum = 0; count > 1; count -= 2)
        sum += *addr++; //每16个bit相加，注意addr的类型是uint16_t
    if (count == 1)
        sum += (char)*addr; //如果是奇数大小则取低八位

    sum = (sum >> 16) + (sum & 0xFFFF); //溢出位加到低位上
    sum += (sum >> 16);
    
    return ~sum; //按位取反
}

//计算数据包tcp头中的校验和
//http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;  //offset,header length
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;  //TCP length

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

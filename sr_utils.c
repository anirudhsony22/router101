#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

uint16_t get_checksum(uint16_t *buf, int count)
{
    register uint32_t sum = 0;

    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            sum &= 0xFFFF;
            sum++;
        }
    }
    sum = ~sum;
    return sum ? sum : 0xffff;
}

int validate_ipchecksum(uint8_t *packet)
{
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

    uint16_t temp_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    int header_len = ip_hdr->ip_hl * 4;
    uint16_t cksum = get_checksum((uint16_t *)ip_hdr, header_len / 2);
    ip_hdr->ip_sum = temp_sum;

    return (cksum == temp_sum);
}

int is_valid_ip_packet(uint8_t *packet)
{

    int is_correct_checksum = validate_ipchecksum(packet);
    if (is_correct_checksum)
    {
        printf("checksum is correct\n");
    }
    else
    {
        printf("checksum is wrong\n");
        return 0;
        // Handle ICMP here
    }

    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    if ((ip_hdr->ip_ttl - 1) == 0)
    {
        // Handle ICMP here
        printf("TTL 0 found");
        return 0;
    }

    return 1;
}

int is_valid_ethernet_packet(unsigned int len) {
        /* Ensure the packet length is valid */
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        fprintf(stderr, "** Error: packet is too short\n");
        return 0;
    }

    return 1;
}

void print_drop() {
    printf("Dropping the packet!!!\n");
}

void print_message(const char *message) {
    printf("-------- %s\n", message);
}

void update_ethernet_header(uint8_t *packet, struct sr_if *iface)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
}

void prepare_arp_reply(struct sr_instance *sr, struct sr_if *iface, struct sr_arphdr *req_hdr, unsigned char *src_mac, char *interface)
{
    // change the operation
    req_hdr->ar_op = htons(ARP_REPLY);

    // Swap MAC addresses
    memcpy(req_hdr->ar_tha, req_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(req_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

    // Swap IP addresses
    uint32_t temp_ip = req_hdr->ar_sip;
    req_hdr->ar_sip = req_hdr->ar_tip;
    req_hdr->ar_tip = temp_ip;
}

void handle_arp(struct sr_instance *sr,
                uint8_t *packet /* lent */,
                unsigned int len,
                char *interface /* lent */)
{

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
    struct sr_if *iface = sr_get_interface(sr, interface);

    if (ntohs(arp_hdr->ar_op) == ARP_REQUEST)
    {
        print_message("Processing ARP Request");
        /* Check if the ARP request is for one of our router's interfaces */
        if (iface && iface->ip == arp_hdr->ar_tip)
        {
            print_message("Processing reply - IP matched");
            /* Prepare ARP reply */
            prepare_arp_reply(sr, iface, arp_hdr, eth_hdr->ether_shost, interface);

            // Update Ethernet header
            update_ethernet_header(packet, iface);

            // Send the ARP reply
            sr_send_packet(sr, packet, len, interface);
        }
    }
}
/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #693354266
 * 
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);


        /* Ensure the packet length is valid */
    if (len < sizeof(struct sr_ethernet_hdr)) {
        fprintf(stderr , "** Error: packet is too short\n");
        return;
    }

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP ) {
        /* Handle ARP packet */
        struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
        printf(" --------- got ARP\n ");

        if (ntohs(arp_hdr->ar_op) == ARP_REQUEST) {
            printf("Processing Request\n");
            /* Check if the ARP request is for one of our router's interfaces */
            struct sr_if* iface = sr_get_interface(sr, interface);
            if (iface && iface->ip == arp_hdr->ar_tip) {
		printf("Processing reply - IP matched\n");
                /* Send ARP reply */
                send_arp_reply(sr, iface, arp_hdr, eth_hdr->ether_shost, interface);


                // Update Ethernet header
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

                // Send the ARP reply
                sr_send_packet(sr, packet, len, interface);
            }
        } 
        // else if (arp_hdr->ar_op == htons(arp_op_reply)) {
        //     /* Update ARP cache */
        //     update_arp_cache(sr, arp_hdr->ar_sip, arp_hdr->ar_sha);
        //     /* Process buffered packets */
        //     process_buffered_packets(sr, arp_hdr->ar_sip);
        // }
    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        printf(" --------- got IP\n");
    } else if (ntohs(eth_hdr->ether_type) == IPPROTO_ICMP) {
        printf(" ---------- got ICMP\n");
    }
	else{
	printf("Received an unknown packet type: 0x%04x\n",ntohs(eth_hdr->ether_type));
}
    /* Add IP and ICMP handling here */

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

void send_arp_reply(struct sr_instance* sr, struct sr_if* iface, struct sr_arphdr* req_hdr, unsigned char *src_mac, char* interface) {
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

void update_arp_cache(struct sr_instance* sr, uint32_t ip, unsigned char *mac) {
    /* Add to ARP cache with timestamp */
}

void process_buffered_packets(struct sr_instance* sr, uint32_t ip) {
    /* Send out all buffered packets that were waiting for this ARP reply */
}

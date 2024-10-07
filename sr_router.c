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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#include "sr_utils.c"

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
    print_message("before init ************");
    initialize_variables();
    print_message("after init ************");
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
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    // ask prof wherther to do any kind of length check of the packets
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    if (!is_valid_ethernet_packet(len)) {
        print_drop();
        return;
    }

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    switch (ntohs(eth_hdr->ether_type)) {
        case ETHERTYPE_ARP:

            print_message("ARP");
            handle_arp(sr, packet, len, interface);

            break;
        case ETHERTYPE_IP:

            print_message("IP");
            if (!is_valid_ip_packet(packet)) // also decreasing ttl
            {
                print_drop();
                return;
            }

            populate_ip_header(packet);
            !ENABLE_PRINT ? : print_message("done populate ip header!!!!");
            handle_ip(packet, sr, len, interface);

            break;
        case IPPROTO_ICMP:

            print_message("ICMP");

            break;
        default:
            printf("Received an unknown packet type: 0x%04x\n", ntohs(eth_hdr->ether_type));
            print_drop();
    }
    /* Add IP and ICMP handling here */
} /* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

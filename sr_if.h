/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#define SR_IFACE_NAMELEN 32

struct sr_instance;

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * Node in the interface list for each router
 *
 * -------------------------------------------------------------------------- */

struct sr_if
{
    char name[SR_IFACE_NAMELEN]; // interface name, e.g., eth0, eth1, ...
    unsigned char addr[6]; // Ethernet address of the interface
    uint32_t ip; // IP address of the interface
    uint32_t speed; // not used yet
    volatile uint32_t mask; // mask
    struct sr_if* next;
};

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name);
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t ip_nbo);
void sr_set_ether_mask(struct sr_instance*, uint32_t ip_nbo);
void sr_print_if_list(struct sr_instance*);
void sr_print_if(struct sr_if*);

#endif /* --  sr_INTERFACE_H -- */

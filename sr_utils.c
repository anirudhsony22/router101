//////////////////////////////////////////////////////////////////    library

#include <stdio.h>
#include <assert.h>
#include <pthread.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

//////////////////////////////////////////////////////////////////    define

#define MAX_IP_CACHE 1000
#define MAX_ARP_CACHE 100
#define MAX_ARP_CACHE_TIME 10
#define ENABLE_PRINT 0

/////New Variables defined for No of Packets rec'd&sent//////
int iprecd=0;
int ipsent=0;
int arprecd=0;
int arpsent=0;
int precd=0;
int psent=0;
int pdrop=0;

//////////////////////////////////////////////////////////////////    struct and classes

struct arpcache
{
    uint32_t ipaddr; // big-indian
    uint8_t ether_dhost[6];
    char name[SR_IFACE_NAMELEN];

    uint8_t valid;
    time_t cachetime;
};

struct ipcache
{
    time_t recordtime;
    uint8_t numoftimes;
    time_t lastreqtime;
    uint8_t valid;
    uint32_t nexthop;
    uint8_t nextetheraddr[6];
    char out_ifacename[SR_IFACE_NAMELEN];

    char *in_ifacename;
    uint8_t *packet;
    unsigned int len;
};

//////////////////////////////////////////////////////////////////    Global variables

struct ipcache IP_CACHE[MAX_IP_CACHE];
struct arpcache ARP_CACHE[MAX_ARP_CACHE];
pthread_mutex_t CACHE_LOCK = PTHREAD_MUTEX_INITIALIZER;

//////////////////////////////////////////////////////////////////    Create Methods

uint8_t *create_arp(struct sr_if *iface, uint32_t target_ip)
{
    // Allocate space for a new ARP request  packet
    unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t *packet = (uint8_t *)malloc(len);

    memset(packet, 0, len);

    // Find interface we should be sending the packet out on
    //   struct sr_if *out_iface = sr_iface_for_dst(sr, tip);
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    // Fill in header information
    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr->ar_hrd = htons(ARPHDR_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ARP_REQUEST);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = target_ip;

    return packet;
}

struct arpcache *create_arpcache_entry(uint32_t ipaddr, const uint8_t ether_dhost[6], const char *iface_name) {
    struct arpcache *entry = malloc(sizeof(struct arpcache));
    if (!entry) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    entry->ipaddr = ipaddr;
    memcpy(entry->ether_dhost, ether_dhost, 6);
    strncpy(entry->name, iface_name, SR_IFACE_NAMELEN);
    entry->valid = 1;  // Set valid flag to 1 since it's a fresh entry
    entry->cachetime = time(NULL); // Set current time

    return entry;
}


struct ipcache *create_ipcache_entry(
    uint8_t *packet,
    unsigned int len,
    const char *in_ifacename,
    uint32_t nexthop,
    const uint8_t *nextetheraddr,
    const char *out_ifacename)
{

    // Dynamically allocate memory for the new ipcache entry
    struct ipcache *entry = (struct ipcache *)malloc(sizeof(struct ipcache));
    if (entry == NULL)
    {
        printf("Memory allocation failed while creating an ipcache entry\n");
        return NULL;
    }

    // Set current time as the record time
    entry->recordtime = time(NULL);
    entry->numoftimes = 0;                  // Initialize number of times this entry is used
    entry->lastreqtime = time(NULL); // Set the last request time to the current time
    entry->valid = 1;                       // Mark this entry as valid

    // Set network details
    entry->nexthop = nexthop;
    // memcpy(entry->nextetheraddr, nextetheraddr, 6);                 // DUMMY mac address
    strncpy(entry->out_ifacename, out_ifacename, SR_IFACE_NAMELEN); // Copy outgoing interface name

    // Allocate memory and copy the incoming interface name
    entry->in_ifacename = strdup(in_ifacename);

    // Allocate memory for the packet and copy it
    entry->packet = (uint8_t *)malloc(len);
    if (entry->packet == NULL)
    {
        printf("Failed to allocate memory for packe in the new ipcache entryt\n");
        free(entry->in_ifacename);
        free(entry);
        return NULL;
    }
    memcpy(entry->packet, packet, len);
    entry->len = len;

    return entry;
}

//////////////////////////////////////////////////////////////////    Other Methods

void cleanup_arpcache() { // must be under the lock
    time_t cur_time = time(NULL);
    int ct=0;
    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].valid == 1) {
            time_t diff = cur_time - ARP_CACHE[i].cachetime;
            if (diff > MAX_ARP_CACHE_TIME) {
                ARP_CACHE[i].valid = 0;
            }
            else{
                ct+=1;
            }
        }
    }
    // printf("---------Total Valid ARP Packets = %d -------",ct);
}

uint8_t* lookup_arpcache(u_int32_t target_ip) {
    pthread_mutex_lock(&CACHE_LOCK);

    cleanup_arpcache();
    
    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].valid == 1) {
            if (target_ip == ARP_CACHE[i].ipaddr) {
                pthread_mutex_unlock(&CACHE_LOCK);
                return ARP_CACHE[i].ether_dhost;
            }
        }
    } 

    pthread_mutex_unlock(&CACHE_LOCK);
    return NULL;
}

int buffer_arp_entry(struct arpcache *new_entry) {
    pthread_mutex_lock(&CACHE_LOCK);

    cleanup_arpcache(); 

    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].ipaddr == new_entry->ipaddr) { // Check for IP address match
            // Update the entry with new data
            memcpy(ARP_CACHE[i].ether_dhost, new_entry->ether_dhost, 6);
            strncpy(ARP_CACHE[i].name, new_entry->name, SR_IFACE_NAMELEN);
            ARP_CACHE[i].cachetime = time(NULL); // Update the cache time

            // Validate the entry regardless of its prior state
            ARP_CACHE[i].valid = 1; 
            pthread_mutex_unlock(&CACHE_LOCK);
            return 1;
        }
    }

    // If no matching IP address is found, find an empty or invalid slot to store the new entry
    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (!ARP_CACHE[i].valid) {  // This checks for an invalid or empty slot
            ARP_CACHE[i] = *new_entry;
            ARP_CACHE[i].valid = 1;
            pthread_mutex_unlock(&CACHE_LOCK);
            return 1;
        }
    }

    pthread_mutex_unlock(&CACHE_LOCK);
    return 0; // No space or no invalid entry available
}


int buffer_ip_packet(struct ipcache *new_entry)
{
    pthread_mutex_lock(&CACHE_LOCK);  // Lock the mutex to prevent race conditions
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        if (IP_CACHE[i].valid == 0)
        {                            
            // Copy the content of new_entry to the IP_CACHE at index i
            IP_CACHE[i] = *new_entry; // Dereference new_entry to copy the data
            IP_CACHE[i].valid = 1;    // Mark the entry as valid
            pthread_mutex_unlock(&CACHE_LOCK); // Unlock the mutex
            return 1;                // Return success
        }
    }

    pthread_mutex_unlock(&CACHE_LOCK); // Unlock the mutex
    return 0; // Return failure if no invalid entry was found (array full)
}

void send_relevent_ipcache_entries(struct arpcache* arpcache_entry,  struct sr_instance *sr) 
{
    pthread_mutex_lock(&CACHE_LOCK);  // Lock the mutex to prevent race conditions
    int ip_packet_counter=0;
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        if (IP_CACHE[i].valid == 1){
            ip_packet_counter+=1;
        }
        if (IP_CACHE[i].valid == 1 && IP_CACHE[i].nexthop == arpcache_entry->ipaddr)
        {                            
            uint8_t* packet = IP_CACHE[i].packet;
            struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
            struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

            struct sr_if *next_iface = sr_get_interface(sr, IP_CACHE[i].out_ifacename);
            
            memset(eth_hdr->ether_dhost, arpcache_entry->ether_dhost, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, next_iface->addr, ETHER_ADDR_LEN);

            sr_send_packet(sr, packet, IP_CACHE[i].len, next_iface->name);
            psent+=1;
            ipsent+=1;
            printf("ARP sent: %d -- ARP recd: %d -- IP Sent %d--IP Recd %d\n", arpsent, arprecd, ipsent, iprecd);

            print_message("@@@@@@@@@@@@@@@@@@ Sending IP packet successfully from cache");

            IP_CACHE[i].valid = 0;
        }
    }

    pthread_mutex_unlock(&CACHE_LOCK); // Unlock the mutex
    printf("---------Valid Packets == %d---------\n",ip_packet_counter);
}

void initialize_variables()
{
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        IP_CACHE[i].valid = 0;
    }

    for (int i = 0; i < MAX_ARP_CACHE; i++)
    {
        ARP_CACHE[i].valid = 0;
    }
}

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
        // printf("checksum is correct\n");
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

int is_valid_ethernet_packet(unsigned int len)
{
    /* Ensure the packet length is valid */
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        fprintf(stderr, "** Error: packet is too short\n");
        return 0;
    }

    return 1;
}

void print_drop()
{
    printf("Dropping the packet!!!\n");
}

void print_message(const char *message)
{
    printf("-------- %s\n", message);
}

void update_ethernet_header_arp_reply(uint8_t *packet, struct sr_if *iface)
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

void populate_ip_header(uint8_t *packet)
{
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

    // TTL
    ip_hdr->ip_ttl--;

    // Checksum setup
    ip_hdr->ip_sum = 0;
    int header_len = ip_hdr->ip_hl * 4;
    ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, header_len / 2);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////    Handling Methods

// char* ip_to_string(uint32_t ip) {

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
            update_ethernet_header_arp_reply(packet, iface);

            // Send the ARP reply
            sr_send_packet(sr, packet, len, interface);
            arpsent+=1;
            psent+=1;
            printf("ARP sent: %d -- ARP recd: %d -- IP Sent %d--IP Recd %d\n", arpsent, arprecd, ipsent, iprecd);
        }
    } else {
        print_message("Processing ARP Reply");
        struct arpcache* new_arpcache = create_arpcache_entry(arp_hdr->ar_sip, arp_hdr->ar_sha, interface);
        int success = buffer_arp_entry(new_arpcache);

        if (!success) {
            print_message("Alert!!!: ARP buffer full! Cannot put the arp entry into the buffer!");
        } else {
            print_message("ARP added to Cache");
            send_relevent_ipcache_entries(new_arpcache, sr);
        }
    }
}

void handle_ip(uint8_t *packet,
               struct sr_instance *sr,
               unsigned int len,
               char *interface /* lent */
)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    int protocol = ip_hdr->ip_p;
    if (protocol==IPPROTO_ICMP){
        print_message("ICMP packet rec'd");
        // handle_icmp(*packet,len, sr, interface, eth_hdr, ip_hdr);
        // return 1;
    }

    struct sr_rt *routing_table = sr->routing_table;

    struct sr_rt *rt_header = routing_table;
    struct in_addr *next_hop = NULL;
    struct in_addr mask;
    struct in_addr nxthop;
    mask.s_addr = 0;
    nxthop.s_addr = 0;
    char next_interface[SR_IFACE_NAMELEN];

    !ENABLE_PRINT ? : print_message("handle ip 1");


    while (rt_header != NULL)
    {
        !ENABLE_PRINT ? : print_message("handle ip 2");

        if ((rt_header->dest.s_addr & rt_header->mask.s_addr) == ((ip_hdr->ip_dst.s_addr) & rt_header->mask.s_addr) && mask.s_addr <= ntohl(rt_header->mask.s_addr))
        {
            mask.s_addr = ntohl(rt_header->mask.s_addr);
            nxthop.s_addr = rt_header->gw.s_addr; // big-endian format
            memcpy(next_interface, rt_header->interface, sizeof(next_interface));
        }
        rt_header = rt_header->next;
    }
    !ENABLE_PRINT ? : print_message("handle ip 3");


    if (nxthop.s_addr == 0)
    {
        !ENABLE_PRINT ? : print_message("handle ip A");
        !ENABLE_PRINT ? :  printf("%u\n", nxthop.s_addr);
        !ENABLE_PRINT ? :  printf("%u\n", rt_header->dest.s_addr);

        nxthop.s_addr = ip_hdr->ip_dst.s_addr;
                        !ENABLE_PRINT ? :  print_message("handle ip B");

    }

    // printf("-------- found next hop for IP: %u\n", nxthop.s_addr);
    struct sr_if* next_iface = sr_get_interface(sr, next_interface);

    // looking up cache
    uint8_t* target_mac = lookup_arpcache(nxthop.s_addr);
    printf("-----------target MAC : %u -----------",target_mac);
    if (target_mac == NULL) {
        printf("-----------------!!!!!Didn't find a valid ARP!!!!!----------------\n");
        // save it to buffer
        struct ipcache* new_ipcache = create_ipcache_entry(packet, len, interface, nxthop.s_addr, NULL, next_interface);
        int success = buffer_ip_packet(new_ipcache);

        if (success) {
            // Send ARP if buffer was successful
            uint8_t *arp_packet = create_arp(next_iface, nxthop.s_addr);
            sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), next_interface);
            arpsent+=1;
            psent+=1;
            printf("ARP sent: %d -- ARP recd: %d -- IP Sent %d--IP Recd %d\n", arpsent, arprecd, ipsent, iprecd);
        } else {
            print_message("Dropping this packet: IP Buffer full");
            
            //todo: Send ICMP
            
            return;
        }
    } else {

        printf("Found an existing MAC from ARP Cache\n");

        memset(eth_hdr->ether_dhost, target_mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, next_iface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, len, next_interface);
        ipsent+=1;
        psent+=1;
        printf("ARP sent: %d -- ARP recd: %d -- IP Sent %d--IP Recd %d\n", arpsent, arprecd, ipsent, iprecd);
    }
}


void handle_icmp(uint8_t *packet,
                 unsigned int len,
                 struct sr_instance* sr,
                 char *interface,
                 struct sr_ethernet_hdr* eth_hdr,
                 struct ip* ip_hdr)
{
    print_message("Entered Handle ICMP");
    unsigned int ip_header_length = ip_hdr->ip_hl * 4;

    print_message("Entering Length check");
    printf("len - %d, needed - %d", len, sizeof(struct sr_ethernet_hdr) + ip_header_length + sizeof(struct icmp_hdr));
    if (len < sizeof(struct sr_ethernet_hdr) + ip_header_length + sizeof(struct icmp_hdr)) {
        fprintf(stderr, "Packet too short to contain ICMP header\n");
        return;
    }

    print_message("Abstracting ICMP Header");
    struct icmp_hdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct sr_ethernet_hdr) + ip_header_length);

    print_message("Abstracting ICMP Type");
    uint8_t icmp_type = icmp_hdr->icmp_type;
    print_message("Abstracting ICMP Code");
    uint8_t icmp_code = icmp_hdr->icmp_code;

    // Get destination IP address (already available in ip_hdr)
    uint32_t dest_ip = ip_hdr->ip_dst.s_addr;

    // Check if the destination IP address is one of the router's interfaces
    struct sr_if *iface = sr->if_list;
    int is_for_router = 0;
    while (iface) {
        if (iface->ip == dest_ip) {
            is_for_router = 1;
            break;
        }
        iface = iface->next;
    }

    if (is_for_router) {
        // The ICMP packet is destined for the router itself
        switch (icmp_type) {
            case IPPORT_ECHO:
                printf("------------ICMP ECHO it is-----------");
                // send_icmp_echo_reply(packet, len, sr, interface, eth_hdr, ip_hdr, icmp_hdr);
                break;
            default:
                // For other types, you might log or ignore
                fprintf(stderr, "Unhandled ICMP type %d received for router\n", icmp_type);
                break;
        }
    } else {
        if (ip_hdr->ip_ttl <= 1) {
            // TTL expired, send ICMP Time Exceeded message back to the sender
            printf("ERROR : TTL done");
            // send_icmp_time_exceeded(packet, len, sr, interface, eth_hdr, ip_hdr);
            return;
        }

        // Decrement TTL
        ip_hdr->ip_ttl--;

        // Recalculate IP header checksum
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_header_length);

        // Forward the packet
        // forward_packet(packet, len, sr, interface, eth_hdr, ip_hdr);
    }
}
///////////////////////////////////////////////////////////////////////////////////////////// Dumps


//     struct in_addr ip_addr;
//     ip_addr.s_addr = ip;
//     return inet_ntoa(ip_addr);
// }

// // Function to print MAC address in human-readable format
// void print_mac_address(const char* label, const unsigned char* mac) {
//     printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label, 
//            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
// }

// // Function to print the contents of the ARP header
// void print_arp_header(const struct sr_arphdr* arp_hdr) {
//     printf("Hardware type: %u\n", ntohs(arp_hdr->ar_hrd));
//     printf("Protocol type: %u\n", ntohs(arp_hdr->ar_pro));
//     printf("Hardware address length: %u bytes\n", arp_hdr->ar_hln);
//     printf("Protocol address length: %u bytes\n", arp_hdr->ar_pln);
//     printf("ARP opcode: %u\n", ntohs(arp_hdr->ar_op));
    
//     print_mac_address("Sender hardware address", arp_hdr->ar_sha);
//     printf("Sender IP address: %s\n", ip_to_string(arp_hdr->ar_sip));
    
//     print_mac_address("Target hardware address", arp_hdr->ar_tha);
//     printf("Target IP address: %s\n", ip_to_string(arp_hdr->ar_tip));
// }



// assert(packet);
// assert(len);
// assert(interface);
// assert(nxthop.s_addr);
// assert(next_interface);

// struct ipcache* new_en = create_ipcache_entry(packet, len, interface, nxthop.s_addr, NULL, next_interface);
// buffer_ip_packet(new_en);
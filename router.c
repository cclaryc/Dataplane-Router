#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

struct route_table_entry rtable[100000];
struct arp_table_entry arp_table[100];

int rtable_size;
int arp_table_size;

int comparator_qsort(const void *x, const void *y) {
    const struct route_table_entry *first = (const struct route_table_entry *)x;
    const struct route_table_entry *second = (const struct route_table_entry *)y;

    int lfirst = 0;
	int lsecond = 0;
    uint32_t mfirst = ntohl(first->mask);
    uint32_t msecond = ntohl(second->mask);

    for(int i = 31; i >= 0; i--) {
        if (((mfirst >> i) & 1) == 1) {
    	lfirst++;
}else break;
    }

    for(int i = 31; i >= 0; i--) {
        if (((msecond >> i) & 1) == 1) {
    	lsecond++;
}else break;
    }

    if(lfirst > lsecond)
	 return -1;
    if(lfirst < lsecond) 
		return 1;
    if(first->prefix < second->prefix)
	 return -1;
    if(first->prefix > second->prefix)
	 return 1;

    return 0;
}

struct route_table_entry *callculate_rout(uint32_t dest_ip) {
    struct route_table_entry *entry = rtable;
    struct route_table_entry *end = rtable + rtable_size;
    while (entry < end) {
        if (entry->prefix == (dest_ip & entry->mask)) {
            return entry;
        }
        entry++;
    }
    return NULL;
}

struct arp_table_entry *return_arp(uint32_t ip) {
    struct arp_table_entry *entry = arp_table;
    struct arp_table_entry *end = arp_table + arp_table_size;
    while (entry < end) {
        if (entry->ip == ip) {
            return entry;
        }
        entry++;
    }
    return NULL;
}
void send_icmp_packet(char *buf, size_t len, int interface, uint8_t tip, uint8_t code, int err) {
	
	
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

	if (err) {
		char reply[MAX_PACKET_LEN];
		memset(reply, 0, MAX_PACKET_LEN);

		struct ether_hdr *eth_reply = (struct ether_hdr *)reply;
		struct ip_hdr *ip_reply = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));
		struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

		memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
		get_interface_mac(interface, eth_reply->ethr_shost);
		eth_reply->ethr_type = htons(0x0800);
		ip_reply->ver = 4;
		ip_reply->ihl = 5;
		ip_reply->tos = 0;
		ip_reply->id = htons(0);
		ip_reply->frag = 0;
		ip_reply->ttl = 64;
		ip_reply->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
		ip_reply->checksum = 0;
		ip_reply->proto = 1;
		ip_reply->source_addr = inet_addr(get_interface_ip(interface));
		ip_reply->dest_addr = ip_hdr->source_addr;

		ip_reply->checksum = htons(checksum((uint16_t *)ip_reply, sizeof(struct ip_hdr)));

		icmp_hdr->mtype = tip;
		icmp_hdr->mcode = code;
		icmp_hdr->check = 0;
		icmp_hdr->un_t.gateway_addr = 0;
		memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);
		size_t icmp_payload_len = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
		icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_payload_len));

		send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_payload_len, reply, interface);
	} else {
		struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

		uint8_t tmp_mac[6];
		memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
		memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
		memcpy(eth_hdr->ethr_dhost, tmp_mac, 6);
		get_interface_mac(interface, eth_hdr->ethr_shost);

		uint32_t tmp_ip = ip_hdr->source_addr;
		ip_hdr->source_addr = ip_hdr->dest_addr;
		icmp_hdr->mtype = tip;
		icmp_hdr->mcode = code;
		icmp_hdr->check = 0;
		ip_hdr->dest_addr = tmp_ip;
		size_t icmp_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);
		icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));
		ip_hdr->ttl = 64;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
		send_to_link(len, buf, interface);
	}
}

int main(int argc, char *argv[]) {
	rtable_size = read_rtable("rtable0.txt", rtable);
	arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator_qsort);
		char buf[MAX_PACKET_LEN];
	init(argv + 2, argc - 2);

	while (1) {
		size_t len;
		size_t interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr))
			continue;

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		uint8_t my_mac[6];
		get_interface_mac(interface, my_mac);
		int not_bbc = 0;
		for (int i = 0; i < 6; i++) {
  		  if (eth_hdr->ethr_dhost[i] != 0xFF) {
        	not_bbc = 1;
        	break;
    }
}

		
		if (memcmp(eth_hdr->ethr_dhost, my_mac, 6) != 0 && not_bbc != 0)
			continue;

		if (ntohs(eth_hdr->ethr_type) != 0x0800)
			continue;

		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		struct route_table_entry *best_route = callculate_rout(ip_hdr->dest_addr);
		if (!best_route) {
			send_icmp_packet(buf, len, interface, 3, 0, 1);
			continue;
		}


		uint16_t original_checksum = ip_hdr->checksum;
		ip_hdr->checksum = 0;
		if (checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4) != ntohs(original_checksum))
			continue;
		ip_hdr->checksum = original_checksum;

		int keepin_it = 0;
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (ip_hdr->dest_addr == inet_addr(get_interface_ip(i))) {
				keepin_it = 1;
				break;
			}
		}

		if (keepin_it && ip_hdr->proto == 1) {
			struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			if (icmp_hdr->mtype == 8) {
				send_icmp_packet(buf, len, interface, 0, 0, 0);
			}
			continue;
		}

		if (ip_hdr->ttl <= 1) {
			send_icmp_packet(buf, len, interface, 11, 0, 1);
			continue;
		}
		ip_hdr->ttl--;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	uint32_t next_hop_ip;
	if (best_route->next_hop) {
		next_hop_ip = best_route->next_hop;
	} else {
		next_hop_ip = ip_hdr->dest_addr;
	}		
	struct arp_table_entry *arp_entry = return_arp(next_hop_ip);
		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
		get_interface_mac(best_route->interface, eth_hdr->ethr_shost);

		send_to_link(len, buf, best_route->interface);
	}
}
#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x806	/* ARP protocol */

struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len) {
	for (int i = 0; i < rtable_len; i++) {
	    if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
	      return &rtable[i];
	    }
	}
	return NULL;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip, struct arp_table_entry *mac_table, int mac_table_len) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip)
			return &(mac_table[i]);
	}
	return NULL;
}

int compare(const void *a, const void *b) {
	struct route_table_entry *aa = (struct route_table_entry *)a;
	struct route_table_entry *bb = (struct route_table_entry *)b;

	return bb->mask - aa->mask;
}

void send_icmp_timeout_or_unreachable(char *buf, int len, int interface, int type) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	char *aux_buf = malloc(sizeof(struct iphdr));
	memcpy(aux_buf, ip_hdr, sizeof(struct iphdr));
	char *send_buf = buf;

	size_t first_ip_place = sizeof(struct ether_header);
	size_t icmp_place = first_ip_place + sizeof(struct iphdr);
	size_t second_ip_place = icmp_place + 8;
	size_t payload_place = second_ip_place + sizeof(struct iphdr);

	memcpy(send_buf + payload_place, (char *)ip_hdr + sizeof(struct iphdr), 8);
	memcpy(send_buf + second_ip_place, ip_hdr, sizeof(struct iphdr));

	char *aux[6];
	memcpy(aux, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux, 6);

	memcpy(send_buf, eth_hdr, sizeof(struct ether_header));


	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + 16);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 100;
	ip_hdr->check = 0;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->protocol = 1;

	struct icmphdr icmp_hdr;
	icmp_hdr.type = type;
	icmp_hdr.code = 0;
	icmp_hdr.checksum = 0;
	icmp_hdr.un.echo.id = 0;
	icmp_hdr.un.echo.sequence = 0;
	
	memcpy(send_buf + second_ip_place, aux_buf, sizeof(struct iphdr));

	memcpy(send_buf + icmp_place, &icmp_hdr, 8);
	icmp_hdr.checksum = htons(checksum((uint16_t *)(send_buf + icmp_place), 28));
	memcpy(send_buf + icmp_place, &icmp_hdr, 8);

	uint16_t sum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->check = sum;

	send_to_link(interface, send_buf, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + 20);
}

void send_icmp_reply(char *buf, int interface, int len) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->check = 0;
	uint16_t sum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->check = sum;

	icmp_hdr->type = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header)) - sizeof(struct iphdr));

	char *aux[6];
	memcpy(aux, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux, 6);

	send_to_link(interface, buf, len);
}

void send_arp_reply(char *buf, int len, struct arp_table_entry *mac_table, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	uint8_t mac[6];
	get_interface_mac(interface, mac);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, mac, 6);

	arp_hdr->op = htons(2);
	uint32_t aux = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = aux;

	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	memcpy(arp_hdr->sha, mac, 6);

	send_to_link(interface, buf, len);
}

void send_arp_request(struct route_table_entry *best_route) {
	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
	char *buf = malloc(len);
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	

	send_to_link(best_route->interface, buf, len);
}

// void manage_arp_packet(char *buf, int len, struct arp_table_entry *mac_table, int interface) {
// 	struct ether_header *eth_hdr = (struct ether_header *) buf;
// 	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

// 	if (arp_hdr->op == 1) {
// 		send_arp_reply(buf, len, mac_table, interface);
// 		return;
// 	}
// }

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	struct arp_table_entry *mac_table = malloc(sizeof(struct arp_table_entry) * 20);
	int rtable_len = read_rtable(argv[1], rtable);
	// int	mac_table_len = parse_arp_table("arp_table.txt", mac_table);
	int mac_table_len = 0;
	queue buf_queue = queue_create();

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		// printf("Mi a dat pachet\n");


		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP) && ntohs(arp_hdr->op) == 1) {
			printf("Am primit ARP\n");
			send_arp_reply(buf, len, mac_table, interface);
			continue;
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}
		if (ip_hdr->protocol == 1 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {
				send_icmp_reply(buf, interface, len);
				continue;
			}
		}
		uint16_t sum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != sum)
			continue;
		
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len);
		if (best_route == NULL) {
			send_icmp_timeout_or_unreachable(buf, len, interface, 3);
			continue;
		}
		
		if (ip_hdr->ttl <= 1) {
			send_icmp_timeout_or_unreachable(buf, len, interface, 11);
			continue;
		}
		ip_hdr->ttl--;
		sum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		ip_hdr->check = sum;

		uint8_t mac[6];
		get_interface_mac(best_route->interface, mac);
		struct arp_table_entry *destmac = get_mac_entry(best_route->next_hop, mac_table, mac_table_len);

		if (destmac == NULL) {
			char *aux_buf = malloc(len * sizeof(char));
			queue_enq(buf_queue, aux_buf);
			send_arp_request(best_route);
			continue;
		}

		for (int i = 0; i < 6; i++) {
			eth_hdr->ether_dhost[i] = destmac->mac[i];
			eth_hdr->ether_shost[i] = mac[i];
		}
		send_to_link(best_route->interface, buf, len);
	}
}


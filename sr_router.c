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
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
/*blahbalbha*/

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
	
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
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

  if(ethertype(packet) == ethertype_ip)
  {
    printf("--------\n");
    int eth_head_len = sizeof(sr_ethernet_hdr_t);
    sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_head = (sr_ip_hdr_t *) (packet + eth_head_len);
    /*print_hdrs(packet, len);*/
    printf("IP PACKET RECEIVED\n");
    printf("From: \n");
    print_addr_eth(eth_head->ether_shost);
    print_addr_ip_int(ntohl(ip_head->ip_src));
    printf("To: \n");
    print_addr_eth(eth_head->ether_dhost);
    print_addr_ip_int(ntohl(ip_head->ip_dst));
    if(cksum(ip_head, ip_head->ip_hl*4) == 65535)
    {
      printf("IP CHECKSUM PASSED\n");
    }
    else 
    {
      printf("IP CHECKSUM FAILED\n");
    }
    printf("--------\n");  
  }
  else if(ethertype(packet) == ethertype_arp)
  {
    printf("ARP PACKET RECEIVED\n");
    int eth_head_len = sizeof(sr_ethernet_hdr_t);
    sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t *arp_head = (sr_arp_hdr_t *) (packet + eth_head_len);
    if(arp_head->ar_tip == sr_get_interface(sr, interface)->ip)
    {
        uint8_t *arp_reply = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sizeof(uint8_t));
        sr_ethernet_hdr_t * rep_eth_head = (sr_ethernet_hdr_t *) arp_reply;
        sr_arp_hdr_t * rep_arp_head = (sr_arp_hdr_t *) (arp_reply + sizeof(sr_ethernet_hdr_t));

        rep_eth_head->ether_type = ntohs(ethertype_arp);
        memcpy(rep_eth_head->ether_dhost, eth_head->ether_shost, ETHER_ADDR_LEN);
	memcpy(rep_eth_head->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
	/*print_addr_eth(rep_eth_head->ether_shost);*/

	rep_arp_head->ar_hrd = ntohs(arp_hrd_ethernet);
	rep_arp_head->ar_pro = arp_head->ar_pro;
	rep_arp_head->ar_hln = arp_head->ar_hln;
	rep_arp_head->ar_pln = arp_head->ar_pln;
	rep_arp_head->ar_op = ntohs(arp_op_reply);
	memcpy(rep_arp_head->ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
	rep_arp_head->ar_sip = arp_head->ar_tip;
	memcpy(rep_arp_head->ar_tha, arp_head->ar_sha, ETHER_ADDR_LEN);
	rep_arp_head->ar_tip = arp_head->ar_sip;
        /*print_hdrs(arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));*/
	sr_send_packet(sr, arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

    }
    printf("From: \n");
    print_addr_eth(eth_head->ether_shost);
    print_addr_ip_int(ntohl(arp_head->ar_sip));
    printf("To: \n");
    print_addr_eth(eth_head->ether_dhost);
    print_addr_ip_int(ntohl(arp_head->ar_tip));
    printf("--------\n");
    /*print_addr_ip_int(ntohl(arp_head->ar_tip)); */
    /*sr_arpcache_queuereq(&sr->cache, arp_head->ar_tip, packet, len, interface);*/
    /*struct sr_arpreq* temp_req = sr->cache.requests;
    while(temp_req != NULL)
    {
      //printf("IP: %d\n", temp_req->sent);
      struct sr_packet* temp_packets = temp_req->packets;
      while(temp_packets != NULL)
      {
        print_hdrs(temp_packets->buf, temp_packets->len);
        temp_packets = temp_packets->next;
      }
      temp_req = temp_req->next;
    }*/
    /*sr_arpcache_dump(&sr->cache);*/
    /*print_hdr_arp(arp_head);*/
    /*print_hdrs(packet, len);*/
  }
  /*printf("Ethertype: %d \n", ethertype(packet));*/
  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */

}/* end sr_ForwardPacket */


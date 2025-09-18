#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
#include <chrono>
#include <mutex>


uint16_t checksum(const void* buf, size_t len);
uint16_t tcpChecksum(const iphdr* ip, const tcphdr* tcp, const uint8_t* payload, size_t plen);
void synScan(const char* TARGET_IPV4, const char* MY_SUPER_SPECIAL_PRIVATE_OMEGA_IPV4, int START_PORT, int STOP_PORT, int CONNECTION_TIMEOUT);

std::mutex mtx;

int main() {
    const char* MY_SUPER_SPECIAL_PRIVATE_OMEGA_IPV4 = "XXX.XXX.XXX.XXX";
    const char* TARGET_IPV4 = "XXX.XXX.XXX.XXX";
    const int START_PORT = 1;
    const int STOP_PORT = 10000;
    const int THREAD_NUMBER = 200;
    const int CONNECTION_TIMEOUT = 3;

    int PORT_CHUNK = (STOP_PORT - START_PORT + 1) / THREAD_NUMBER;

    std::vector<std::thread> threads;

   for (int i = 0; i < THREAD_NUMBER; i++) {
        int end = (i == THREAD_NUMBER - 1) ? STOP_PORT : PORT_CHUNK*(i+1);
        threads.emplace_back(synScan, TARGET_IPV4, MY_SUPER_SPECIAL_PRIVATE_OMEGA_IPV4, START_PORT+(i*PORT_CHUNK), end, CONNECTION_TIMEOUT);
   }

   for (std::thread &t : threads) {
        t.join();
   }
    

    return 0;
}

void synScan(const char* TARGET_IPV4, const char* MY_SUPER_SPECIAL_PRIVATE_OMEGA_IPV4, int START_PORT, int STOP_PORT, int CONNECTION_TIMEOUT) {
    for (int port = START_PORT; port <= STOP_PORT; port++) {
        int soc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);   // Put sockets on

        if (soc < 0) {
            std::perror("socket");  // Did you put sockets on correctly?
            return;
        }

        
        int opt = 1;
        if (setsockopt(soc, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(soc))) { // Make sockets from scratch
            std::perror("IP_HDRINCL");  // God said no for some reasson
            return;
        }

        sockaddr_in addr;   // Person who will get packet (He lives in Brazil)
        addr.sin_family = AF_INET; // IPv4
        inet_pton(AF_INET, TARGET_IPV4, &addr.sin_addr); // Make the shipping text Portuguese


        uint8_t packet[4096]; // Box size
        memset(&packet, 0, sizeof(packet)); // Fill the box with air

        iphdr* ip = (iphdr*) packet;    // Address on the box
        tcphdr* tcp = (tcphdr*) (packet + sizeof(iphdr));   // Idk what to type for this

        ip->ihl = 5;            // Header length
        ip->version = 4;        // IPv4
        ip->tos = 0;            // Type of service
        ip->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr)); // Total length of packet
        ip->id = htons(54321);
        ip->frag_off = 0;       // No fragmentation (Packet not that big)
        ip->ttl = 64;           // How many planes could carry tha packet before it explodes
        ip->protocol = IPPROTO_TCP;     // Self explanatory
        inet_pton(AF_INET, MY_SUPER_SPECIAL_PRIVATE_OMEGA_IPV4, &ip->saddr);   // My address
        inet_pton(AF_INET, TARGET_IPV4, &ip->daddr);                         // His address
        ip->check = checksum(ip, sizeof(iphdr));

        std::random_device rd;                          // very VERY SCNARY C++ ADVANED RANDOM STUFF
        std::mt19937 gen(rd());                         // PROCEED WITH CAUTION
        std::uniform_int_distribution<uint32_t> dis;    // PROCEED WITH CAUTION
                                                        //          ^
                                                        //          |
        tcp->source = htons(40000);     // Source port              |
        tcp->dest = htons(port);       // Destination port          |
        tcp->seq = htonl(dis(gen));     // Sequence number----------|
        tcp->ack_seq = 0;               // No ACK, This is SYN
        tcp->doff = 5;                  // Data offset (tcp header length in 32-bit words)
        tcp->syn = 1;                   // SYN flag to init connection
        tcp->window = htons(65535);     // Advertisied window size (How manx bytes host can recive before stopping and waiting for ACK), set to max 16-bit
        tcp->check = 0;                 // Zero out checksum placeholder before big scary math
        tcp->urg_ptr = 0;               // urgent pointer not used
        tcp->check = tcpChecksum(ip, tcp, nullptr, 0);      // Compute tcp checksum

        if (sendto(soc, packet, sizeof(iphdr) + sizeof(tcphdr), // Send out packet
        0, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::perror("sendto SYN");
            close(soc);
            return;
        }

        auto now = std::chrono::high_resolution_clock::now();

        uint8_t buf[4096];
        while (true) {
            ssize_t rec = recv(soc, buf, sizeof(buf), 0);       // Receive packet
            if (rec <= 0) {
                continue;
            }

            iphdr* recIp = (iphdr*) buf;                        // Get recieved ip header
            if (recIp->protocol != IPPROTO_TCP) {
                continue;
            }

            tcphdr* recTcp = (tcphdr*) (buf + recIp->ihl*4);    // Skip to the START_PORT of tcp hdr

            if (recIp->saddr == ip->daddr && recTcp->source == tcp->dest) { // If the packet is from requested source
                if (recTcp->syn && recTcp->ack) {
                    //std::cout << "SYN-ACK detected. Sending RST...\n";

                    uint8_t rstPck[4096];                           // RST packet
                    memset(rstPck, 0, sizeof(rstPck));              // Zero out RST packet

                    iphdr* ipRst = (iphdr*) rstPck;                 // Create ip header for RST
                    tcphdr* tcpRst = (tcphdr*) (sizeof(iphdr) + rstPck);    // Create tcp header for RST

                    memcpy(ipRst, ip, sizeof(iphdr));               // Copy SYN packet's ip header into RTS's one, with different checksum
                    ipRst->check = 0;
                    ipRst->check = checksum(ipRst, sizeof(iphdr));

                    tcpRst->source = tcp->source;                   // Setup new tcp header
                    tcpRst->dest = tcp->dest;
                    tcpRst->seq = recTcp->ack_seq;
                    tcpRst->ack_seq = 0;
                    tcpRst->doff = 5;
                    tcpRst->rst = 1;
                    tcpRst->window = 0;
                    tcpRst->check = 0;
                    tcpRst->check = tcpChecksum(ipRst, tcpRst, nullptr, 0);


                    if (sendto(soc, rstPck, sizeof(iphdr) + sizeof(tcphdr),         // Tell destination host that it is ugly and you dont want to see it no more
                    0, (sockaddr*)&addr, sizeof(addr)) < 0) {
                        std::perror("sendto RST");
                    } else {
                        mtx.lock();
                        std::cout << port << " is open\n";
                        mtx.unlock();
                        //std::cout << "RST SENT\n";
                    }
                    break;
                }
            }

            auto nowerNow = std::chrono::high_resolution_clock::now();

            int duration = std::chrono::duration_cast<std::chrono::seconds>(nowerNow - now).count();
            
            if (duration >= CONNECTION_TIMEOUT) {
                break;
            }
        }

        close(soc); // Happy ending
    }
}

uint16_t checksum(const void* buf, size_t len) { // Bullshit math
    const uint16_t* data = (const uint16_t*)buf;
    uint32_t sum = 0;
    while (len > 1) { 
        sum += *data++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t*)data;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

uint16_t tcpChecksum(const iphdr* ip, const tcphdr* tcp, const uint8_t* payload, size_t plen) {
    struct pseudo_header {
        uint32_t src, dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } psh;
                            // Even more bullshit math
    psh.src = ip->saddr;
    psh.dst = ip->daddr;
    psh.zero = 0; 
    psh.proto = IPPROTO_TCP;
    psh.len = htons(sizeof(tcphdr) + plen);

    size_t bufsize = sizeof(psh) + sizeof(tcphdr) + plen;
    std::vector<uint8_t> buf(bufsize);
    memcpy(buf.data(), &psh, sizeof(psh));
    memcpy(buf.data() + sizeof(psh), tcp, sizeof(tcphdr));
    if (plen > 0) memcpy(buf.data() + sizeof(psh) + sizeof(tcphdr), payload, plen);

    return checksum(buf.data(), buf.size());
}
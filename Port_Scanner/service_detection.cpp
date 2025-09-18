#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <vector>
#include <map>
#include <mutex>

void scanChunk(const int START_PORT, const int STOP_PORT, const int CONNECTION_TIMEOUT);
int sendAll(int soc, const char* payload, size_t len);
std::string makeHttpsProbe(const std::string &host);

const char* TARGET_IPV4 = "XXX.XXX.XXX.XXX";
const std::string HTTP_PROBE = "GET / HTTP/1.1\r\nHost: " + (std::string)TARGET_IPV4 + "\r\nConnection: close\r\n\r\n";
const std::string HTTPS_PROBE = makeHttpsProbe(TARGET_IPV4);
std::mutex mtx;

std::map<int, std::pair<std::string, std::string>> probes = {
    {80,    {HTTP_PROBE, "HTTP"}},
    {8080,  {HTTP_PROBE, "HTTP"}},
    {8000,  {HTTP_PROBE, "HTTP"}},
    {8888,  {HTTP_PROBE, "HTTP"}},

    {443,   {
        HTTPS_PROBE, 
        "HTTPS"
    }},
    {8443,  {
        HTTPS_PROBE, 
        "HTTPS"
    }},
    {8444,  {
        HTTPS_PROBE, 
        "HTTPS"
    }},

    {53,    {
        "\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x01"
        "\x00\x00\xff\x00\x01",
        "DNS_TCP"
    }},

    {5432,  {
        "\x00\x00\x00\x1a"
        "\x00\x03\x00\x00"
        "user\x00postgres\x00"
        "\x00",
        "PostgreSQL"
    }},

    {445,   {
        "\x00\x00\x00\x54"
        "\xff\x53\x4d\x42"
        "\x72\x00\x00\x00\x00\x18\x53\xc8"
        "\x00\x26\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x62\x00\x02\x50\x43\x20\x4e"
        "\x45\x54\x57\x4f\x52\x4b\x20\x50"
        "\x52\x4f\x47\x52\x41\x4d\x20\x31"
        "\x2e\x30\x00\x02\x4c\x41\x4e\x4d"
        "\x41\x4e\x31\x2e\x30\x00\x02\x57"
        "\x69\x6e\x64\x6f\x77\x73\x20\x66"
        "\x6f\x72\x20\x57\x6f\x72\x6b\x67"
        "\x72\x6f\x75\x70\x73\x20\x33\x2e"
        "\x31\x00",
        "SMB"
    }},
    {139,   {
        "\x00\x00\x00\x54"
        "\xff\x53\x4d\x42"
        "\x72\x00\x00\x00\x00\x18\x53\xc8"
        "\x00\x26\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x62\x00\x02\x50\x43\x20\x4e"
        "\x45\x54\x57\x4f\x52\x4b\x20\x50"
        "\x52\x4f\x47\x52\x41\x4d\x20\x31"
        "\x2e\x30\x00\x02\x4c\x41\x4e\x4d"
        "\x41\x4e\x31\x2e\x30\x00\x02\x57"
        "\x69\x6e\x64\x6f\x77\x73\x20\x66"
        "\x6f\x72\x20\x57\x6f\x72\x6b\x67"
        "\x72\x6f\x75\x70\x73\x20\x33\x2e"
        "\x31\x00",
        "SMB"
    }},

    {389,   {
        "\x30\x1c"
        "\x02\x01\x01"
        "\x60\x17"
        "\x02\x01\x03"
        "\x04\x00"
        "\x80\x10" "anonymouspw",
        "LDAP"
    }},
    {636,   {
        "\x30\x1c"
        "\x02\x01\x01"
        "\x60\x17"
        "\x02\x01\x03"
        "\x04\x00"
        "\x80\x10" "anonymouspw",
        "LDAP"
    }},

    {6379,  {"*1\r\n$4\r\nPING\r\n", "Redis"}},

    {11211, {"version\r\n", "Memcached"}},

    {9200,  {"GET / HTTP/1.0\r\n\r\n", "Elasticsearch"}},
    {9300,  {"GET / HTTP/1.0\r\n\r\n", "Elasticsearch"}},

    {27017, {
        "\x3a\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\xd4\x07\x00\x00"
        "\x00"
        "\x00"
        "\x05hello\x00\x00"
        "\x00", 
        "MongoDB"
    }},

    {5672,  {"AMQP\x00\x00\x09\x01", "RabbitMQ"}}
};



int main()
{
    const int CONNECTION_TIMEOUT = 3;
    const int START_PORT = 1;
    const int STOP_PORT = 10000;
    const int THREAD_NUMBER = 200;
    const int PORT_CHUNK = (STOP_PORT - START_PORT + 1) / THREAD_NUMBER;

    std::vector<std::thread> threads;

    for (int i = 0; i < THREAD_NUMBER; i++) {
        int end = (i == THREAD_NUMBER - 1) ? STOP_PORT : PORT_CHUNK*(i+1);

        threads.emplace_back(scanChunk, START_PORT+(i*PORT_CHUNK), end, CONNECTION_TIMEOUT);
    }

    for (std::thread &t : threads) {
        t.join();
    }

    return 0;
}

void scanChunk(const int START_PORT, const int STOP_PORT, const int CONNECTION_TIMEOUT)
{
    for (int port = START_PORT; port <= STOP_PORT; port++){

        int soc = socket(AF_INET, SOCK_STREAM, 0);

        int flags = fcntl(soc, F_GETFL, 0);
        fcntl(soc, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);



        if (inet_pton(AF_INET, TARGET_IPV4, &serverAddress.sin_addr) <= 0) {
            close(soc);
            return;
        }
        
        int res = connect(soc, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        if (res < 0 && errno == EINPROGRESS) {
            fd_set readFd, writeFd;
            FD_ZERO(&readFd);
            FD_SET(soc, &readFd);
            FD_ZERO(&writeFd);
            FD_SET(soc, &writeFd);

            struct timeval disconnectTime;
            disconnectTime.tv_sec = CONNECTION_TIMEOUT;
            disconnectTime.tv_usec = 0;

            if (select(soc+1, &readFd, &writeFd, nullptr, &disconnectTime) > 0) {

                if (FD_ISSET(soc, &writeFd)) {
                    int err;
                    socklen_t socLen = sizeof(err);
                    getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &socLen);

                    if (err == 0) {
                        for (const auto &probePair : probes) {
                            if (port == probePair.first) {
                                if (sendAll(soc, probes[port].first.c_str(), probes[port].first.size()) < 0) {
                                    std::cerr << "Failed to send probe";
                                    close(soc);
                                }
                                break;
                            }
                        }

                        fd_set readFdReceived;
                        FD_ZERO(&readFdReceived);
                        FD_SET(soc, &readFdReceived);

                        struct timeval disconnectTimeReceived;
                        disconnectTimeReceived.tv_sec = CONNECTION_TIMEOUT;
                        disconnectTimeReceived.tv_usec = 0;

                        if (select(soc+1, &readFdReceived, nullptr, nullptr, &disconnectTimeReceived) > 0) {
                            char buffer[4096];

                            int outputReceived = recv(soc, &buffer, sizeof(buffer) - 1, 0);

                            mtx.lock();
                            std::cout << "Port " << port << " is open\n";
                            std::cout << probes[port].second << "\n";

                            if (outputReceived > 0) {
                                buffer[outputReceived] = '\0';
                                std::cout << buffer << "\n";
                            }
                            mtx.unlock();
                        }
                    }
                }
                if (FD_ISSET(soc, &readFd)) {
                    int err;
                    socklen_t socLen = sizeof(err);
                    getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &socLen);

                    if (err == 0) {
                        char buffer[4096];
                        int outputReceived = recv(soc, &buffer, sizeof(buffer) - 1, 0);

                        mtx.lock();
                        std::cout << "Port " << port << " is open\n";

                        if (outputReceived > 0) {
                            buffer[outputReceived] = '\0';
                            std::cout << buffer << "\n";
                        }
                        mtx.unlock();
                    }
                }

                
            }
        }
        else if (res == 0) {
            fd_set readFd;
            FD_ZERO(&readFd);
            FD_SET(soc, &readFd);

            struct timeval disconnectTime;
            disconnectTime.tv_sec = CONNECTION_TIMEOUT;
            disconnectTime.tv_usec = 0;

            if (select(soc+1, &readFd, nullptr, nullptr, &disconnectTime) > 0) {
                int err;
                socklen_t socLen = sizeof(err);
                getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &socLen);

                if (err == 0) {
                    char buffer[4096];
                    int outputReceived = recv(soc, &buffer, sizeof(buffer) - 1, 0);

                    mtx.lock();
                    std::cout << "Port " << port << " is open\n";

                    if (outputReceived > 0) {
                        buffer[outputReceived] = '\0';
                        std::cout << buffer << "\n";
                    }
                    mtx.unlock();
                }

                
            }
        }

        close(soc);
    }
}

int sendAll(int soc, const char* PAYLOAD, size_t len) {
    size_t totalSent = 0;

    while (totalSent < len) {
        ssize_t sent = send(soc, PAYLOAD + totalSent, len - totalSent, 0);
        if (sent <= 0) {
            if (sent < 0) {
                std::cerr << "send() error: " << strerror(errno) << "\n";
            }
            return -1;
        }
        totalSent += sent;
    }
    
    return totalSent;
}

std::string makeHttpsProbe(const std::string &host) {
    std::string sni = host;

    std::string probe =
        "\x16\x03\x01\x00\xdc"
        "\x01\x00\x00\xd8"
        "\x03\x03"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\x00" 
        "\x00\x20"
        "\x00\x9c\x00\x9d\x00\x2f\x00\x35"
        "\x00\x0a\xc0\x2f\xc0\x30\xc0\x2b"
        "\xc0\x2c\xc0\x13\xc0\x14\x00\x9e"
        "\x00\x9f"
        "\x01"
        "\x00"
        "\x00";

    std::string sniExt;
    sniExt += "\x00\x00";
    uint16_t sniLen = sni.size() + 5;
    sniExt += std::string(1, (sniLen >> 8) & 0xFF);
    sniExt += std::string(1, sniLen & 0xFF);
    sniExt += "\x00" "\x00";
    uint16_t nameLen = sni.size() + 3;
    sniExt += std::string(1, (nameLen >> 8) & 0xFF);
    sniExt += std::string(1, nameLen & 0xFF);
    sniExt += "\x00";
    sniExt += std::string(1, (sni.size() >> 8) & 0xFF);
    sniExt += std::string(1, sni.size() & 0xFF);
    sniExt += sni;

    uint16_t totalExtLen = sniExt.size();
    probe += std::string(1, (totalExtLen >> 8) & 0xFF);
    probe += std::string(1, totalExtLen & 0xFF);
    probe += sniExt;

    return probe;
}
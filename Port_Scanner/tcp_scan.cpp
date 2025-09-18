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


void scanChunk(const int START_PORT, const int STOP_PORT, const char* TARGET_IPV4, const int CONNECTION_TIMEOUT);

std::mutex mtx;

int main()
{
    const char* TARGET_IPV4 = "XXX.XXX.XXX.XXX";
    const int CONNECTION_TIMEOUT = 3;
    const int START_PORT = 1;
    const int STOP_PORT = 10000;
    const int THREAD_NUMBER = 200;
    const int PORT_CHUNK = (STOP_PORT - START_PORT + 1) / THREAD_NUMBER;

    std::vector<std::thread> threads;

    for (int i = 0; i < THREAD_NUMBER; i++) {
        int end = (i == THREAD_NUMBER - 1) ? STOP_PORT : PORT_CHUNK*(i+1);

        threads.emplace_back(scanChunk, START_PORT+(i*PORT_CHUNK), end, TARGET_IPV4, CONNECTION_TIMEOUT);
    }

    for (std::thread &t : threads) {
        t.join();
    }

    return 0;
}

void scanChunk(const int START_PORT, const int STOP_PORT, const char* TARGET_IPV4, const int CONNECTION_TIMEOUT)
{
    for (int port = START_PORT; port <= STOP_PORT; port++){

        int soc = socket(AF_INET, SOCK_STREAM, 0);
        if (soc < 0) {
            std::perror("socket");
            return;
        }

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

            struct timeval tv;
            tv.tv_sec = CONNECTION_TIMEOUT;
            tv.tv_usec = 0;

            if (select(soc+1, &readFd, &writeFd, nullptr, &tv) > 0) {  
                int err;
                socklen_t socLen = sizeof(err);
                getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &socLen);

                if (err == 0) {
                    mtx.lock();
                    std::cout << "Port " << port << " is open\n";
                    mtx.unlock();
                }

                
            }
        }
        else if (res == 0) {
            fd_set readFd;
            FD_ZERO(&readFd);
            FD_SET(soc, &readFd);

            struct timeval tvRead;
            tvRead.tv_sec = CONNECTION_TIMEOUT;
            tvRead.tv_usec = 0;

            if (select(soc+1, &readFd, nullptr, nullptr, &tvRead) > 0) {
                int err;
                socklen_t socLen = sizeof(err);
                getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &socLen);

                if (err == 0) {
                    mtx.lock();
                    std::cout << "Port " << port << " is open\n";
                    mtx.unlock();
                }

                
            }
        }

        close(soc);
    }
}
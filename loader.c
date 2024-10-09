#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include "bpf_load.h"


int open_raw_sock(const char *name) {

    struct ifreq ifr;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("SO_BINDTODEVICE");
        exit(1);
    }

    return sock;
}

int main(int argc, char **argv) {
    int sock = -1, i, key;
    int tcp_cnt, udp_cnt, icmp_cnt;

    // BPF 프로그램 파일 이름 설정
    char filename[256];
    snprintf(filename, sizeof(filename), "%s", argv[1]);

    // BPF 프로그램 로드
    if (load_bpf_file(filename)) {
        printf("%s", bpf_log_buf); // 오류 시 로그 출력
        return 1;
    }

    // 로컬 네트워크 인터페이스(lo)에서 raw socket 열기
    sock = open_raw_sock("lo");

    // BPF 프로그램을 소켓에 Attach
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd, sizeof(prog_fd[0]))) {
        printf("setsockopt %s\n", strerror(errno));
        return 0;
    }

    for (i = 0; i < 10; i++) {
        key = IPPROTO_TCP;
        assert(bpf_map_lookup_elem(map_fd[0], &key, &tcp_cnt) == 0);

        key = IPPROTO_UDP;
        assert(bpf_map_lookup_elem(map_fd[0], &key, &udp_cnt) == 0);

        key = IPPROTO_ICMP;
        assert(bpf_map_lookup_elem(map_fd[0], &key, &icmp_cnt) == 0);

        printf("TCP %d UDP %d ICMP %d packets\n", tcp_cnt, udp_cnt, icmp_cnt);
        sleep(1);
    }
}

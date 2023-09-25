/* Decrypt packets using keys dumped by dump_keys.gdb in real-time */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <openssl/evp.h>
#include <openssl/provider.h>

void hexdump(const uint8_t *data, size_t len) {
    int a = 0;
    while (a < len) {
        int cols = 16;
        if (a + cols >= len)
            cols = len - a;

        printf("%04x  ", a);

        for (int i = 0; i < cols; i++) {
            if (i == 8)
                putchar(' ');
            printf("%02x ", data[a + i]);
        }

        int pad = 3 * (16 - cols) + 1;
        if (cols <= 8)
            pad++;
        for (int i = 0; i < pad; i++)
            putchar(' ');

        for (int i = 0; i < cols; i++) {
            char c = data[a + i];
            printf("%c", ' ' <= c && c <= '~' ? c : '.');
        }

        printf("\n");
        a += cols;
    }
    printf("\n");
}

#define DES1_KEY_LEN 8
#define DES3_KEY_LEN (3 * DES1_KEY_LEN)
#define MAX_KEY_LEN DES3_KEY_LEN

int main(int argc, char **args) {
    int key_count = argc - 1;
    char **key_files = args + 1;

    uint8_t *keys = malloc(MAX_KEY_LEN * key_count);
    size_t *key_lengths = malloc(sizeof(size_t) * key_count);
    for (int i = 0; i < key_count; i++) {
        FILE *f = fopen(key_files[i], "r");
        size_t len = fread(keys + (MAX_KEY_LEN * i), 1, MAX_KEY_LEN, f);
        assert(len == DES1_KEY_LEN || len == DES3_KEY_LEN);
        key_lengths[i] = len;
        fclose(f);
    }

    EVP_CIPHER *des3_cipher = EVP_CIPHER_fetch(NULL, "des-ede3-cbc", NULL);
    OSSL_PROVIDER_load(NULL, "legacy");
    EVP_CIPHER *des1_cipher = EVP_CIPHER_fetch(NULL, "des", "provider=legacy");
    assert(des3_cipher);
    assert(des1_cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    assert(ctx);

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        uint8_t packet[2048];
        ssize_t len = recv(sockfd, packet, sizeof(packet), 0);
        struct ether_header *eth = (struct ether_header *)packet;
        struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
        uint8_t *contents = (uint8_t *)udp + sizeof(*udp);

        /* esp header */
        int8_t crypt = *(uint8_t *)contents;
        uint32_t spi = *(uint32_t *)contents;
        uint32_t seq = ntohl(*(uint32_t *)(contents + 0x4));
        uint8_t *iv = (uint8_t *)(contents + 0x8);
        uint8_t *msg = (uint8_t *)(contents + 0x10);

        int game_packet =
            ntohl(ip->saddr) == 1 && ntohs(udp->source) == 3074 && ntohs(udp->dest) == 3074;
        if (!game_packet)
            continue;

        EVP_CIPHER *cipher = NULL;
        uint8_t const *key = NULL;
        for (int i = 0; i < key_count; i++) {
            char *slash = strrchr(key_files[i], '/');
            char *spi_i = slash ? slash + 1 : key_files[i];
            if (strtol(spi_i, NULL, 16) == spi) {
                key = keys + MAX_KEY_LEN * i;
                cipher = key_lengths[i] == DES1_KEY_LEN ? des1_cipher : des3_cipher;
                break;
            }
        }
        if (!key) {
            continue;
            printf("no matching key for SPI: %08x, len: %ld\n", spi, len);
        }

        int out_len = 0;
        ssize_t msg_len =
            len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct udphdr) - 0xc;

        if (crypt) {
            uint8_t decrypted[sizeof(packet)];
            msg_len -= 0x10; /* esp header */
            assert(EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL));
            assert(EVP_DecryptUpdate(ctx, decrypted, &out_len, (void *)msg, msg_len));
            assert(out_len == msg_len);
            msg = decrypted;
        }

        printf("spi=%04x seq=%08x len=%lu crypt=%d\n", spi, seq, len, crypt);
        hexdump(msg, msg_len);
    }
}

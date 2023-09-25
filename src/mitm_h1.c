/* Perform an MITM attack between two instance of Halo: Combat Evolved playing
 * over System Link.
 *
 * Usage:
 * - Connect two or more consoles and a computer to a network switch.
 * - Start this program on the computer: ./mitm_h1 <game_region> <net_ifc>.
 * - Start a System Link game from one of the consoles.
 * - Join the game from the other console (if -DSNEAKY is not used, make sure
 *   to join the game that ends with (mitm)).
 * - Confirm that the decrypted messages are printed by the program.
 * - Play with the current packet alterations or modify the program to perform
 *   any custom alterations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define UDP_PORT 3074
#define IP_SRC 1 /* 0.0.0.1 */

#define BUFSIZE 2048 /* enough to fit any packet */

#define ICV_LEN 12
#define IV_LEN 8

#define HMAC_BLOCK_LEN 64
#define HMAC_KEY_LEN 16
#define HMAC_OUT_LEN 20

#define DES1_KEY_LEN 8
#define DES3_KEY_LEN (3 * DES1_KEY_LEN)

#define LAN_KEY_LEN 16

const static uint8_t MAC_BROADCAST[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* xboxkrnl export ordinal 353 */
const static uint8_t LAN_KEY_XBOX[2][LAN_KEY_LEN] = {
    /* NTSC */
    {0xf5, 0xba, 0x02, 0xac, 0x27, 0x3d, 0xb2, 0x95, 0x8c, 0xb8, 0x43, 0xdf, 0xdd, 0xbf, 0x4f,
     0xa7},
    /* PAL */
    {0xc5, 0x4f, 0x1a, 0x3b, 0x3a, 0x1f, 0x97, 0x12, 0x70, 0xc3, 0x81, 0xae, 0x56, 0xad, 0x1f,
     0x91},
};

const static uint8_t LAN_KEY_TITLE[2][LAN_KEY_LEN] = {
    /* NTSC */
    {0xe5, 0x8f, 0x4b, 0x95, 0x6b, 0xa7, 0x45, 0x43, 0x53, 0x31, 0xd0, 0xdd, 0x1d, 0xdc, 0x67,
     0x15},
    /* PAL */
    {0xf3, 0xca, 0x14, 0xd9, 0x9b, 0x92, 0x82, 0xcb, 0xf7, 0x9d, 0x53, 0xb3, 0x9d, 0x67, 0x11,
     0xfb},
};

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
}

void cbc_crypt(int enc, int des3, uint8_t const *key, uint8_t const *iv, uint8_t *inout,
               size_t len) {
    static EVP_CIPHER_CTX *ctx = NULL;
    static EVP_CIPHER *des3_cipher = NULL;
    static EVP_CIPHER *des1_cipher = NULL;

    if (!ctx) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        des3_cipher = EVP_CIPHER_fetch(NULL, "des-ede3-cbc", NULL);
        OSSL_PROVIDER_load(NULL, "legacy");
        des1_cipher = EVP_CIPHER_fetch(NULL, "des", "provider=legacy");

        assert(ctx);
        assert(des3_cipher);
        assert(des1_cipher);
    }

    const EVP_CIPHER *cipher = des3 ? des3_cipher : des1_cipher;
    int out_len = 0;

    assert(EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, NULL));
    assert(EVP_CipherUpdate(ctx, inout, &out_len, inout, len));
    assert(out_len == len);
}

void hmac(uint8_t const *key, uint8_t const *data0, size_t data0_len, uint8_t const *data1,
          size_t data1_len, uint8_t *out) {
    static EVP_MD_CTX *ctx = NULL;
    static EVP_MD *sha1 = NULL;
    static uint8_t buf[HMAC_BLOCK_LEN];
    static uint8_t h0[HMAC_OUT_LEN];

    if (!ctx) {
        ctx = EVP_MD_CTX_new();
        sha1 = EVP_MD_fetch(NULL, "sha1", NULL);
        assert(ctx);
        assert(sha1);
    }

    for (int i = 0; i < HMAC_BLOCK_LEN; i++)
        buf[i] = (i < HMAC_KEY_LEN ? key[i] : 0) ^ 0x36;
    unsigned int h0_len = 0;
    assert(EVP_DigestInit_ex2(ctx, sha1, NULL));
    assert(EVP_DigestUpdate(ctx, buf, HMAC_BLOCK_LEN));
    if (data0)
        assert(EVP_DigestUpdate(ctx, data0, data0_len));
    if (data1)
        assert(EVP_DigestUpdate(ctx, data1, data1_len));
    assert(EVP_DigestFinal_ex(ctx, h0, &h0_len));
    assert(h0_len == HMAC_OUT_LEN);

    for (int i = 0; i < HMAC_BLOCK_LEN; i++)
        buf[i] = (i < HMAC_KEY_LEN ? key[i] : 0) ^ 0x5c;
    unsigned int out_len = 0;
    assert(EVP_DigestInit_ex2(ctx, sha1, NULL));
    assert(EVP_DigestUpdate(ctx, buf, HMAC_BLOCK_LEN));
    assert(EVP_DigestUpdate(ctx, h0, HMAC_OUT_LEN));
    assert(EVP_DigestFinal_ex(ctx, out, &out_len));
    assert(out_len == HMAC_OUT_LEN);
}

static const uint8_t DES_PARITY[16] = {
    0x00, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x03, 0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
};

void des_key_parity(uint8_t *key, size_t len) {
    for (int i = 0; i < len; i++) {
        uint8_t pl = DES_PARITY[key[i] & 0x0f];
        uint8_t pu = DES_PARITY[key[i] >> 4];
        if ((pl + pu) % 2 == 0)
            key[i] ^= 0x01;
    }
}

struct ether_header *packet_eth(uint8_t *p) { return (struct ether_header *)p; }

struct iphdr *packet_ip(uint8_t *p) {
    return (struct iphdr *)((void *)packet_eth(p) + sizeof(struct ether_header));
}

struct udphdr *packet_udp(uint8_t *p) {
    return (struct udphdr *)((void *)packet_ip(p) + sizeof(struct iphdr));
}

uint8_t *packet_payload(uint8_t *p) { return (void *)packet_udp(p) + sizeof(struct udphdr); }

struct esp {
    int8_t crypt;
    uint8_t spi[2];
    int8_t _3h;
    uint32_t seq;
    uint8_t iv[IV_LEN];
    uint8_t msg[]; /* variable length */
    /* 12-byte ICV after msg */
};

struct esp *packet_esp(uint8_t *p) { return (struct esp *)packet_payload(p); }

#define MOD_EXP_LEN 0x60

static const uint8_t MOD_EXP_ONE[MOD_EXP_LEN] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

enum packet_type {
    BROADCAST_G2H = 0x00,
    HANDSHAKE = 0x01,
    BROADCAST_H2G = 0x02,
    INGAME_H2G = 0x14,
    INGAME_G2H = 0x19,
};

/* guest searching for games */
struct broadcast_g2h {
    struct udphdr udp;
    uint16_t packet_size; /* (0x10 << 4) | 0xc */
    uint8_t _ah;          /* 01 */
    uint8_t udp_port_guest[0x2];
    uint8_t _eh[0x2]; /* 00 01 */
    uint8_t guest_id[0x8];
    uint8_t packet_type; /* 00 */
};

/* host responding to search */
struct broadcast_h2g {
    struct udphdr udp;
    uint16_t packet_size; /* (0x118 << 4) | 0xc */
    uint8_t _ah;          /* 01 */
    uint8_t guest_id[0x8];
    uint8_t host_id[0x8];
    uint8_t hmac_data0[0x8];
    uint8_t hmac_data1[0x10];
    uint8_t _33h[0x2]; /* 0c 00 */
    uint8_t mac_src[ETH_ALEN];
    uint8_t _3bh[0x9]; /* 00 00 00 00 20 14 01 00 00 */
    char host[0x20];
    uint8_t _58h[0x1f]; /* 00 .. */
    char level_path[0x7f];
    uint16_t game_rules;
    uint16_t _104h; /* 00 01 */
    uint16_t number_of_players;
    uint16_t _108h; /* 00 10 */
    uint16_t score_limit;
    uint16_t mode;
    uint8_t _10eh; /* 00 */
    uint8_t game_status[0x4];
    uint8_t age_in_a_bot[0xc];
    uint8_t packet_type; /* 02 */
};

/* first package exchanged between clients during handshake (unencrypted, not ESP) */
struct handshake {
    uint8_t _0h[0xc];              /* 00 00 00 00 00 XX XX 00 00 00 00 00 */
    uint8_t hmac_data1_guest[0x8]; /* randomized by guest */
    uint8_t hmac_data1_host[0x8];  /* randomized by host */
    uint8_t mod_exp_base[MOD_EXP_LEN];
    uint8_t broadcast_hmac_data0[0x8];
    uint8_t _7ch[0x2]; /* 0c 00 */
    uint8_t mac_src[ETH_ALEN];
    uint8_t _84h[0xb];   /* 00 00 00 00 XX XX XX e9 fc d8 d9 */
    uint8_t packet_type; /* 01 */
};

enum action {
    CROUCH = 1 << 0x0,            /* left stick */
    JUMP = 1 << 0x1,              /* A */
    TOGGLE_FLASHLIGHT = 1 << 0x4, /* white */
    RELOAD = 1 << 0x6,            /* X */
    MELEE = 1 << 0x7,             /* B */
    FIRE = 1 << 0xb,              /* right trigger */
    THROW_GRENADE0 = 1 << 0xc,    /* left trigger */
    THROW_GRENADE1 = 1 << 0xd,    /* left trigger */
    PICK_UP = 1 << 0xe,           /* X hold */
};

struct player {
    uint32_t actions;
    float yaw;
    float pitch;
    float forward;
    float left;
    float fire_duration;
    int16_t selected_weapon;
    int16_t selected_grenade;
    int16_t zoom;
};

/* network player array contains 4-byte elements but is not 4-byte aligned */
#define PLAYER_SIZE (sizeof(struct player) - 2)

/* sent from each guest to the host once every tick */
struct ingame_g2h {
    struct udphdr udp;
    uint16_t packet_size; /* (0x09 + player_count * 0x1e) << 4 | 0xc */
    uint8_t _10h;         /* 01 */
    uint8_t tick[0x4];
    uint8_t player_count;
    struct player players[]; /* only player on guest console */
};

/* sent from the host to every guest once every tick */
struct ingame_h2g {
    struct tcphdr tcp;
    uint16_t packet_size; /* ((0x11 + player_count * 0x1e) << 4) | 0xc */
    uint8_t _16h;         /* 01 */
    uint8_t tick_a[0x4];
    uint8_t hash[0x4]; /* XX XX XX XX */
    uint8_t tick_b[0x4];
    uint8_t player_count;
    struct player players[]; /* all players in game */
};

float ntohf(float f) {
    uint32_t i = ntohl(*(uint32_t *)&f);
    return *(float *)&i;
}

float htonf(float f) {
    uint32_t i = htonl(*(uint32_t *)&f);
    return *(float *)&i;
}

void player_print(struct player *p) {
    printf("  actions: ");
    for (int a = 1; a != 0; a <<= 1) {
        switch (ntohl(p->actions) & a) {
        case CROUCH:
            printf("crouch ");
            break;
        case JUMP:
            printf("jump ");
            break;
        case TOGGLE_FLASHLIGHT:
            printf("toggle_flashlight ");
            break;
        case RELOAD:
            printf("reload ");
            break;
        case MELEE:
            printf("melee ");
            break;
        case FIRE:
            printf("fire ");
            break;
        case THROW_GRENADE0:
            printf("throw_grenade0 ");
            break;
        case THROW_GRENADE1:
            printf("throw_grenade1 ");
            break;
        case PICK_UP:
            printf("pick_up ");
            break;
        }
    }
    printf("\n");
    printf("  yaw: %f\n", htonf(p->yaw));
    printf("  pitch: %f\n", htonf(p->pitch));
    printf("  forward: %f\n", htonf(p->forward));
    printf("  left: %f\n", htonf(p->left));
    printf("  fire_duration: %f\n", htonf(p->fire_duration));
    printf("  selected_weapon: %d\n", (int16_t)htons(p->selected_weapon));
    printf("  selected_grenade: %d\n", (int16_t)htons(p->selected_grenade));
    printf("  zoom: %d\n", (int16_t)htons(p->zoom));
}

struct mitm {
    int sockfd;

    struct timespec time_recv;

    uint8_t title_icv_key[HMAC_KEY_LEN];
    uint8_t title_des3_key[DES3_KEY_LEN];

    uint8_t mac_mitm[ETH_ALEN];
    uint8_t mac_guest[ETH_ALEN];
    uint8_t mac_host[ETH_ALEN];

    int has_sa;

    uint8_t hs_icv_key[HMAC_KEY_LEN];

    /* for messages encrypted by guests */
    uint8_t sa_icv_key_guest[HMAC_KEY_LEN];
    uint8_t sa_des_key_guest[DES1_KEY_LEN];

    /* for messages encrypted by hosts */
    uint8_t sa_icv_key_host[HMAC_KEY_LEN];
    uint8_t sa_des_key_host[DES1_KEY_LEN];
};

void mitm_reset(struct mitm *m) {
    clock_gettime(CLOCK_REALTIME, &m->time_recv);
    memset(m->mac_guest, 0, ETH_ALEN);
    memset(m->mac_host, 0, ETH_ALEN);
    m->has_sa = 0;
}

void mitm_init(struct mitm *m, char *net_ifc, uint8_t const *xbox_key, uint8_t const *title_key) {
    struct ifreq ifr;
    strcpy(ifr.ifr_name, net_ifc);

    m->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m->sockfd == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(m->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&timeout, sizeof(timeout));

    /* bind to an interface in order to be able to send packets */
    size_t ret_ifindex = ioctl(m->sockfd, SIOCGIFINDEX, &ifr);
    assert(ret_ifindex == 0);
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = ifr.ifr_ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    if (bind(m->sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    static const uint8_t ZERO = 0;
    static const uint8_t ONE = 1;
    uint8_t buf[HMAC_OUT_LEN];

    hmac(xbox_key, &ZERO, 1, title_key, LAN_KEY_LEN, buf);
    memcpy(m->title_icv_key, buf, HMAC_KEY_LEN);
    memcpy(m->title_des3_key, buf + HMAC_KEY_LEN, HMAC_OUT_LEN - HMAC_KEY_LEN);
    hmac(xbox_key, &ONE, 1, title_key, LAN_KEY_LEN,
         m->title_des3_key + HMAC_OUT_LEN - HMAC_KEY_LEN);
    des_key_parity(m->title_des3_key, DES3_KEY_LEN);

    /* use actual mac address of interface to ensure packets addressed to MITM
     * reaches our device */
    size_t ret_ifhwaddr = ioctl(m->sockfd, SIOCGIFHWADDR, &ifr);
    assert(ret_ifhwaddr == 0);
    memcpy(m->mac_mitm, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    mitm_reset(m);
}

void mitm_step(struct mitm *m) {
    struct timespec time_now;
    clock_gettime(CLOCK_REALTIME, &time_now);
    uint64_t duration_ms = (time_now.tv_sec * 1000 + time_now.tv_nsec / 1000000) -
                           (m->time_recv.tv_sec * 1000 + m->time_recv.tv_nsec / 1000000);
    /* reset if no package received for too long */
    if (duration_ms > 2500)
        mitm_reset(m);

    uint8_t p[BUFSIZE];
    ssize_t p_len = recv(m->sockfd, p, sizeof(p), 0);
    if (p_len == -1)
        return;
    int game_packet = ntohl(packet_ip(p)->saddr) == IP_SRC &&
                      ntohs(packet_udp(p)->source) == UDP_PORT &&
                      ntohs(packet_udp(p)->dest) == UDP_PORT;
    if (!game_packet)
        return;

    int broadcast = memcmp(MAC_BROADCAST, packet_eth(p)->ether_dhost, ETH_ALEN) == 0;
    int unicast = memcmp(m->mac_mitm, packet_eth(p)->ether_dhost, ETH_ALEN) == 0;
    if (!broadcast && !unicast)
        return;
    if (broadcast && m->has_sa)
        return;

    int h2g = memcmp(m->mac_host, packet_eth(p)->ether_shost, ETH_ALEN) == 0;
    int g2h = !h2g;

    printf("crypt: %d, spi: %04x, seq %08x, _3h: %d, len: %lu\n", packet_esp(p)->crypt,
           ntohs(*(uint16_t *)packet_esp(p)->spi), ntohl(packet_esp(p)->seq), packet_esp(p)->_3h,
           ntohs(packet_udp(p)->len) - sizeof(struct udphdr));

    ssize_t pl_len = p_len - sizeof(struct ether_header) - sizeof(struct iphdr) -
                     sizeof(struct udphdr) - ICV_LEN;

    uint8_t *icv_key = broadcast    ? m->title_icv_key
                       : !m->has_sa ? m->hs_icv_key
                       : h2g        ? m->sa_icv_key_host
                                    : m->sa_icv_key_guest;
    uint8_t icv[HMAC_OUT_LEN];
    hmac(icv_key, packet_payload(p), pl_len, NULL, 0, icv);
    uint8_t *icv_expected = packet_payload(p) + pl_len;
    if (memcmp(icv, icv_expected, ICV_LEN) != 0) {
        printf("ICV check failed, ignoring packet\n");
        return;
    }

    clock_gettime(CLOCK_REALTIME, &m->time_recv);

    uint8_t *msg = packet_payload(p);
    size_t msg_len = pl_len;

    uint8_t *esp_key = broadcast ? m->title_des3_key
                       : h2g     ? m->sa_des_key_host
                                 : m->sa_des_key_guest;

    if (packet_esp(p)->crypt) {
        msg_len -= sizeof(struct esp);
        cbc_crypt(false, broadcast, esp_key, packet_esp(p)->iv, packet_esp(p)->msg, msg_len);

        uint8_t next_header = packet_esp(p)->msg[--msg_len];
        assert(next_header == IPPROTO_UDP || next_header == IPPROTO_TCP);
        uint8_t pad_length = packet_esp(p)->msg[--msg_len];
        while (pad_length--)
            assert(packet_esp(p)->msg[--msg_len] == pad_length + 1);

        msg = packet_esp(p)->msg;

        /* verify packet size field */
        size_t packet_size_ofs =
            next_header == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr);
        uint16_t packet_size = ntohs(*(uint16_t *)(msg + packet_size_ofs));
        assert((packet_size & 0xf) == 0xc);
        assert(msg[packet_size_ofs + 2] == 0x01);
        packet_size >>= 4;
        assert(packet_size_ofs + packet_size == msg_len);
    }

    enum packet_type ty = msg[msg_len - 1];

    switch (ty) {
    case BROADCAST_H2G: {
        struct broadcast_h2g *broadcast_h2g = (struct broadcast_h2g *)msg;

        memcpy(m->mac_host, broadcast_h2g->mac_src, ETH_ALEN);
        hmac(m->title_icv_key, broadcast_h2g->hmac_data0, sizeof(broadcast_h2g->hmac_data0),
             broadcast_h2g->hmac_data1, sizeof(broadcast_h2g->hmac_data1), m->hs_icv_key);

#ifndef SNEAKY
        /* use separate host id and game name to guest client can distinguish
         * from original */
        memcpy(broadcast_h2g->host_id, "BESTHOST", 0x8);

        /* annotate mitm game name so player can distinguish from original */
        static char *appendum = " (mitm)";
        ssize_t host_len = 0;
        while (broadcast_h2g->host[host_len + 1] && host_len + 2 < sizeof(broadcast_h2g->host))
            host_len += 2;
        for (ssize_t i = 0; i < strlen(appendum); i++) {
            int j = host_len + 2 * i + 1;
            if (j >= sizeof(broadcast_h2g->host) - 2)
                break;
            broadcast_h2g->host[j] = appendum[i];
        }
#endif

        memcpy(broadcast_h2g->mac_src, m->mac_mitm, ETH_ALEN);
        break;
    }
    case HANDSHAKE: {
        struct handshake *handshake = (struct handshake *)msg;
        if (g2h) {
            memcpy(m->mac_guest, handshake->mac_src, ETH_ALEN);

            memcpy(handshake->mod_exp_base, MOD_EXP_ONE, MOD_EXP_LEN);
            memcpy(handshake->mac_src, m->mac_mitm, ETH_ALEN);
        } else if (h2g) {
            uint8_t hmac_data0[1 + sizeof(handshake->hmac_data1_guest) +
                               sizeof(handshake->hmac_data1_host)];
            uint8_t hmac_out[HMAC_OUT_LEN];

            memcpy(hmac_data0 + 1, handshake->hmac_data1_guest, 8);
            memcpy(hmac_data0 + 9, handshake->hmac_data1_host, 8);

            hmac_data0[0] = 1;
            hmac(m->hs_icv_key, hmac_data0, sizeof(hmac_data0), MOD_EXP_ONE, MOD_EXP_LEN, hmac_out);
            memcpy(m->sa_icv_key_guest, hmac_out, HMAC_KEY_LEN);

            hmac_data0[0] = 2;
            hmac(m->hs_icv_key, hmac_data0, sizeof(hmac_data0), MOD_EXP_ONE, MOD_EXP_LEN, hmac_out);
            memcpy(m->sa_des_key_guest, hmac_out, DES1_KEY_LEN);
            des_key_parity(m->sa_des_key_guest, DES1_KEY_LEN);

            hmac_data0[0] = 3;
            hmac(m->hs_icv_key, hmac_data0, sizeof(hmac_data0), MOD_EXP_ONE, MOD_EXP_LEN, hmac_out);
            memcpy(m->sa_icv_key_host, hmac_out, HMAC_KEY_LEN);

            hmac_data0[0] = 4;
            hmac(m->hs_icv_key, hmac_data0, sizeof(hmac_data0), MOD_EXP_ONE, MOD_EXP_LEN, hmac_out);
            memcpy(m->sa_des_key_host, hmac_out, DES1_KEY_LEN);
            des_key_parity(m->sa_des_key_host, DES1_KEY_LEN);

            m->has_sa = 1;

            memcpy(handshake->mod_exp_base, MOD_EXP_ONE, MOD_EXP_LEN);
            memcpy(handshake->mac_src, m->mac_mitm, ETH_ALEN);
        }
        break;
    }
    case INGAME_G2H: {
        struct ingame_g2h *game = (struct ingame_g2h *)msg;
        for (int i = 0; i < game->player_count; i++) {
            /* XXX unaligned pointers do not work on all cpus */
            struct player *p = (void *)game->players + i * PLAYER_SIZE;

            printf("guest player %d\n", i);
            player_print(p);

            /* speed boost */
            if (ntohl(p->actions) & TOGGLE_FLASHLIGHT) {
                p->forward = htonf(10 * ntohf(p->forward));
                p->left = htonf(10 * ntohf(p->left));
            }
        }
        break;
    }
    case INGAME_H2G: {
        struct ingame_h2g *game = (struct ingame_h2g *)msg;
        for (int i = 0; i < game->player_count; i++) {
            struct player *p = (void *)game->players + i * PLAYER_SIZE;

            printf("host player %d\n", i);
            player_print(p);
        }
        break;
    }
    case BROADCAST_G2H:
    default: {
        hexdump(msg, msg_len);
    }
    }

    if (packet_esp(p)->crypt) {
        cbc_crypt(true, broadcast, esp_key, packet_esp(p)->iv, packet_esp(p)->msg,
                  pl_len - sizeof(struct esp));
    }

    memcpy(packet_eth(p)->ether_shost, m->mac_mitm, ETH_ALEN);
    if (unicast)
        memcpy(packet_eth(p)->ether_dhost, h2g ? m->mac_guest : m->mac_host, ETH_ALEN);

    hmac(icv_key, packet_payload(p), pl_len, NULL, 0, icv);
    memcpy(packet_payload(p) + pl_len, icv, ICV_LEN);

    int send_len = send(m->sockfd, p, p_len, 0);
    if (send_len == -1) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }
    assert(p_len == send_len);
}

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

int main(int argc, char *args[]) {
    assert(argc == 3);
    char *version = args[1];
    char *net_ifc = args[2];

    int ntsc = strcmp(version, "ntsc") == 0;
    int pal = strcmp(version, "pal") == 0;
    assert(ntsc || pal);

    size_t ifc_len = strnlen(args[1], IFNAMSIZ);
    assert(ifc_len < IFNAMSIZ);

    struct mitm mitm = {};
    mitm_init(&mitm, net_ifc, LAN_KEY_XBOX[pal], LAN_KEY_TITLE[pal]);

    while (1)
        mitm_step(&mitm);
}

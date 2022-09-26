#define READ_KERN(ptr)                                 \
  ({                                                   \
    typeof(ptr) _val;                                  \
    __builtin_memset((void *)&_val, 0, sizeof(_val));  \
    bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
    _val;                                              \
  })

#define READ_USER(ptr)                                      \
  ({                                                        \
    typeof(ptr) _val;                                       \
    __builtin_memset((void *)&_val, 0, sizeof(_val));       \
    bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
    _val;                                                   \
  })

#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define ctx_ptr(field)		(void *)(long)(field)

#define AF_INET 2
#define AF_INET6 10

#define MAX_PERCPU_BUFSIZE 10240
#define MAX_STR_ARR_ELEM 40
#define MAX_STRING_SIZE 4096

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define MAX_DNS_NAME_LENGTH 256

struct dns_hdr
{
  uint16_t transaction_id;
  uint8_t rd : 1;      // Recursion desired
  uint8_t tc : 1;      // Truncated
  uint8_t aa : 1;      // Authoritive answer
  uint8_t opcode : 4;  // Opcode
  uint8_t qr : 1;      // Query/response flag
  uint8_t rcode : 4;   // Response code
  uint8_t cd : 1;      // Checking disabled
  uint8_t ad : 1;      // Authenticated data
  uint8_t z : 1;       // Z reserved bit
  uint8_t ra : 1;      // Recursion available
  uint16_t q_count;    // Number of questions
  uint16_t ans_count;  // Number of answer RRs
  uint16_t auth_count; // Number of authority RRs
  uint16_t add_count;  // Number of resource RRs
};

struct ar_hdr
{
  uint8_t name;
  uint16_t type;
  uint16_t size;
  uint32_t ex_rcode;
  uint16_t rcode_len;
} __attribute__((packed));

struct dns_query
{
  uint16_t record_type;
  uint16_t class;
  char name[MAX_DNS_NAME_LENGTH];
};

struct dns_event
{
  u64 ts;
  u16 r_type;
  u8 is_matched;
  char name[MAX_DNS_NAME_LENGTH];
};

struct a_record
{
  __be32 ip_addr;
  uint32_t ttl;
};

struct dns_response
{
  uint16_t query_pointer;
  uint16_t record_type;
  uint16_t class;
  uint32_t ttl;
  uint16_t data_length;
} __attribute__((packed));

static inline void swap_mac_addresses(struct __sk_buff *skb)
{
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, 6);
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, 6);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, 6, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, 6, 0);
}

#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define DNS_HLEN sizeof(struct dns_hdr)

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CHK_OFF (ETH_HLEN + offsetof(struct iphdr, check))

#define UDP_SPT_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, source))
#define UDP_DPT_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, dest))
#define UDP_CHK_OFF (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check))

static inline void swap_ip_addresses(struct __sk_buff *skb)
{
  u32 src_ip;
  u32 dst_ip;
  bpf_skb_load_bytes(skb, IP_SRC_OFF, &src_ip, 4);
  bpf_skb_load_bytes(skb, IP_DST_OFF, &dst_ip, 4);

  bpf_l3_csum_replace(skb, IP_CHK_OFF, src_ip, dst_ip, sizeof(dst_ip));
  bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);

  bpf_l3_csum_replace(skb, IP_CHK_OFF, dst_ip, src_ip, sizeof(src_ip));
  bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);
}

static inline void swap_upd_port(struct __sk_buff *skb)
{
  u16 src;
  u16 dst;
  bpf_skb_load_bytes(skb, UDP_SPT_OFF, &src, 2);
  bpf_skb_load_bytes(skb, UDP_DPT_OFF, &dst, 2);

  bpf_skb_store_bytes(skb, UDP_SPT_OFF, &dst, sizeof(dst), 0);
  bpf_skb_store_bytes(skb, UDP_DPT_OFF, &src, sizeof(src), 0);

  //更新UDP的checksum为0, UDP不强制要求checksum
  u16 chkSum = 0;
  bpf_skb_store_bytes(skb, UDP_CHK_OFF, &chkSum, sizeof(chkSum), 0);
}

static inline void changeLength(struct __sk_buff *skb, uint16_t iplen, uint16_t udplen)
{
  u16 old_iplen;
  u16 old_udplen;
  bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &old_iplen, 2);
  bpf_skb_load_bytes(skb, ETH_HLEN + IP_HLEN + offsetof(struct udphdr, len), &old_udplen, 2);

  bpf_l3_csum_replace(skb, IP_CHK_OFF, old_iplen, iplen, sizeof(iplen));
  bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &iplen, sizeof(iplen), 0);
  bpf_skb_store_bytes(skb, ETH_HLEN + IP_HLEN + offsetof(struct udphdr, len), &udplen, sizeof(udplen), 0);
}
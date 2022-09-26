#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct dns_heap
{
  char dns_buffer[512];
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct dns_query);
  __type(value, struct a_record);
  __uint(max_entries, 65536);
} dns_a_records SEC(".maps");

/* BPF perfbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_capture_events SEC(".maps");

// 一个 struct event 变量的大小超过了 512 字节，无法放到 BPF 栈上，
// 因此声明一个 size=1 的 per-CPU array 来存放 event 变量
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per-cpu array
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct dns_heap);
} heap SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per-cpu array
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct dns_event);
} eventheap SEC(".maps");

// Parse query and return query length
static inline int parse_query(struct __sk_buff *ctx, void *query_start, struct dns_query *q)
{
  void *data_end = (void *)(long)ctx->data_end;
  uint16_t i;
  void *cursor = query_start;
  int namepos = 0;
  // Fill dns_query.name with zero bytes
  // Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
  memset(&q->name[0], 0, sizeof(q->name));
  // Fill record_type and class with default values to satisfy verifier
  q->record_type = 0;
  q->class = 0;

  // We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
  // We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
  for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
  {
    // Boundary check of cursor. Verifier requires a +1 here.
    // Probably because we are advancing the pointer at the end of the loop
    if (cursor + 1 > data_end)
    {
      break;
    }
    // If separator is zero we've reached the end of the domain query
    if (*(char *)(cursor) == 0)
    {
      // We've reached the end of the query name.
      // This will be followed by 2x 2 bytes: the dns type and dns class.
      if (cursor + 5 > data_end)
      {
        break;
      }
      else
      {
        q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
        q->class = bpf_htons(*(uint16_t *)(cursor + 3));
      }

      // Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
      return namepos + 1 + 2 + 2;
    }
    // Read and fill data into struct
    q->name[namepos] = *(char *)(cursor);
    namepos++;
    cursor++;
  }

  return -1;
}

static inline void modify_dns_header_response(struct dns_hdr *dns_hdr)
{
  // Set query response
  dns_hdr->qr = 1;
  // Set truncated to 0
  // dns_hdr->tc = 0;
  // Set authorative to zero
  // dns_hdr->aa = 0;
  // Recursion available
  dns_hdr->ra = 1;
  // One answer
  dns_hdr->ans_count = bpf_htons(1);
}

static inline void create_query_response(struct a_record *a, char *dns_buffer, size_t *buf_size)
{
  // Formulate a DNS response. Currently defaults to hardcoded query pointer + type a + class in + ttl + 4 bytes as reply.
  struct dns_response *response = (struct dns_response *)&dns_buffer[0];
  response->query_pointer = bpf_htons(0xc00c);
  response->record_type = bpf_htons(0x0001);
  response->class = bpf_htons(0x0001);
  response->ttl = bpf_htonl(a->ttl);
  response->data_length = bpf_htons((uint16_t)sizeof(a->ip_addr));
  *buf_size += sizeof(struct dns_response);
  // Copy IP address
  memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(a->ip_addr));
  *buf_size += sizeof(a->ip_addr);
}

static inline int parse_ar(struct __sk_buff *ctx, struct dns_hdr *dns_hdr, int query_length, struct ar_hdr *ar)
{
  void *data_end = (void *)(long)ctx->data_end;

  // Parse ar record
  ar = (void *)dns_hdr + query_length + sizeof(struct dns_response);
  if ((void *)ar + sizeof(struct ar_hdr) > data_end)
  {
    return -1;
  }

  return 0;
}

static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer, size_t *buf_size)
{
  // Check for OPT record (RFC6891)
  if (ar->type == bpf_htons(41))
  {
    struct ar_hdr *ar_response = (struct ar_hdr *)&dns_buffer[0];
    // We've received an OPT record, advertising the clients' UDP payload size
    // Respond that we're serving a payload size of 512 and not serving any additional records.
    ar_response->name = 0;
    ar_response->type = bpf_htons(41);
    ar_response->size = bpf_htons(512);
    ar_response->ex_rcode = 0;
    ar_response->rcode_len = 0;

    *buf_size += sizeof(struct ar_hdr);
  }
  else
  {
    return -1;
  }

  return 0;
}

static int match_a_records(struct dns_query *q, struct a_record *a)
{
  struct a_record *record;

  record = bpf_map_lookup_elem(&dns_a_records, q);
  // If record pointer is not zero..
  if (record > 0)
  {
    a->ip_addr = record->ip_addr;
    a->ttl = record->ttl;
    return 0;
  }
  return -1;
}
// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int tc_dns_func(struct __sk_buff *ctx)
{
  uint64_t start = bpf_ktime_get_ns();

  int zero = 0;
  struct dns_heap *e;
  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) /* can't happen */
  {
    return 0;
  }

  struct dns_event *dns_e;
  dns_e = bpf_map_lookup_elem(&eventheap, &zero);
  if (!dns_e) /* can't happen */
  {
    return 0;
  }

  void *data_end = ctx_ptr(ctx->data_end);
  void *data = ctx_ptr(ctx->data);
  // Boundary check: check if packet is larger than a full ethernet + ip header
  if (data + ETH_HLEN + IP_HLEN > data_end)
  {
    return TC_ACT_OK;
  }
  struct ethhdr *eth = data;
  // Ignore packet if ethernet protocol is not IP-based
  if (eth->h_proto != bpf_htons(ETH_P_IP))
  {
    return TC_ACT_OK;
  }

  struct iphdr *ip = data + ETH_HLEN;
  if (ip->protocol == IPPROTO_UDP)
  {
    struct udphdr *udp;
    // Boundary check for UDP
    if (data + ETH_HLEN + IP_HLEN + UDP_HLEN > data_end)
    {
      return TC_ACT_OK;
    }
    udp = data + ETH_HLEN + IP_HLEN;
    // Check if dest port equals 53
    if (udp->dest == bpf_htons(53))
    {
      struct dns_hdr *dns_hdr;
      // Boundary check for minimal DNS header
      if (data + ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN > data_end)
      {
        return TC_ACT_OK;
      }
      dns_hdr = data + ETH_HLEN + IP_HLEN + UDP_HLEN;
      // Check if header contains a standard query
      if (dns_hdr->qr == 0 && dns_hdr->opcode == 0)
      {
        // Get a pointer to the start of the DNS query
        void *query_start = (void *)dns_hdr + DNS_HLEN;
        // We will only be parsing a single query for now
        struct dns_query q;
        int query_length = 0;
        query_length = parse_query(ctx, query_start, &q);
        if (query_length < 1)
        {
          return TC_ACT_OK;
        }
        dns_e->r_type = q.record_type;
        memcpy(dns_e->name, q.name, sizeof(dns_e->name));
        size_t buf_size = 0;
        // Check if query matches a record in our hash table
        struct a_record a_record;
        int res = match_a_records(&q, &a_record);
        if (res < 0)
        {
          uint64_t end = bpf_ktime_get_ns();
          dns_e->ts = end - start;
          dns_e->is_matched = 0;
          bpf_perf_event_output(ctx, &dns_capture_events, BPF_F_CURRENT_CPU, dns_e, sizeof(*dns_e));
          return TC_ACT_OK;
        }

        // Change DNS header to a valid response header
        modify_dns_header_response(dns_hdr);

        // Create DNS response and add to temporary buffer.
        create_query_response(&a_record, &e->dns_buffer[buf_size], &buf_size);

        // If an additional record is present 如果请求包中有附加记录
        if (dns_hdr->add_count > 0)
        {
          // Parse AR record
          struct ar_hdr ar;
          if (parse_ar(ctx, dns_hdr, query_length, &ar) != -1)
          {
            // Create AR response and add to temporary buffer
            create_ar_response(&ar, &e->dns_buffer[buf_size], &buf_size);
          }
        }

        // // Start our response [query_length] bytes beyond the header
        void *answer_start = (void *)dns_hdr + DNS_HLEN + query_length;
        // // Determine increment of packet buffer
        int tailadjust = answer_start + buf_size - data;
        // // Adjust packet length accordingly
        if (bpf_skb_change_tail(ctx, tailadjust, 0) < 0)
        {
          return TC_ACT_OK;
        }
        else
        {
          // Because we adjusted packet length, mem addresses might be changed.
          // Reinit pointers, as verifier will complain otherwise.
          data = ctx_ptr(ctx->data);
          data_end = ctx_ptr(ctx->data_end);

          // Copy bytes from our temporary buffer to packet buffer
          int aOffset = ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN + query_length;
          bpf_skb_store_bytes(ctx, aOffset, &e->dns_buffer[0], buf_size, 0);
          eth = data;
          ip = data + ETH_HLEN;
          udp = data + ETH_HLEN + IP_HLEN;

          // Do a new boundary check
          if (data + ETH_HLEN + IP_HLEN + UDP_HLEN > data_end)
          {
            return TC_ACT_OK;
          }
          // Adjust UDP length and IP length
          uint16_t iplen = bpf_htons((data_end - data) - ETH_HLEN);
          uint16_t udplen = bpf_htons((data_end - data) - ETH_HLEN - IP_HLEN);
          changeLength(ctx, iplen, udplen);
          swap_mac_addresses(ctx);
          swap_ip_addresses(ctx);
          swap_upd_port(ctx);

          uint64_t end = bpf_ktime_get_ns();
          dns_e->ts = end - start;
          dns_e->is_matched = 1;
          bpf_perf_event_output(ctx, &dns_capture_events, BPF_F_CURRENT_CPU, dns_e, sizeof(*dns_e));

          // Redirecting the modified skb on the same interface to be transmitted again
          return bpf_redirect(ctx->ifindex, BPF_F_INGRESS);
        }
      }
    }
  }

  return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
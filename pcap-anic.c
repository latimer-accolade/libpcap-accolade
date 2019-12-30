#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "pcap-int.h"

#include <anic_api.h>



// file local defines
#define MAX_ANICS                  4
#define MAX_RINGS                  64
#define ANIC_RING_BLOCKS_DEFAULT   4
#define HUGEPAGE_SIZE              0x200000



// file loacal data structures
struct ring_s {
  anic_handle_t anic_handle;
  uint32_t anic_id;
  uint32_t ring_id;
  uint32_t activated;
  uint32_t blk_count;
  uint32_t nonblocking;
  uint8_t  *blk_buf[ANIC_BLOCK_MAX_BLOCKS];
  uint64_t blk_dma[ANIC_BLOCK_MAX_BLOCKS];
  uint32_t blk_valid;
  uint32_t blk_id;
  uint8_t *buf_p;
  uint8_t *last_p;
  uint32_t packets;
};



// forward function definitions
//static int l_libinit(void);
static int l_anicinit(uint32_t anic_id);
static int l_anicgetids(const char *devname, uint32_t *anic_id, uint32_t *ring_id);
// ...the method functions
static void anic_cleanup(pcap_t *p);
static int anic_activate(pcap_t *p);
static int anic_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
static int anic_inject(pcap_t *p, const void *buf _U_, size_t size _U_);
static int anic_setfilter(pcap_t *p, struct bpf_program *fp);
static int anic_set_datalink(pcap_t *p, int dlt);
static int anic_getnonblock(pcap_t *p, char *errbuf);
static int anic_setnonblock(pcap_t *p, int nonblock, char *errbuf);
static int anic_stats(pcap_t *p, struct pcap_stat *ps);



// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
int anic_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
  *devlistp = NULL;
  return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
pcap_t *anic_create(const char *device, char *ebuf, int *is_ours)
{
  pcap_t *p;
  struct ring_s *rp;
  uint32_t anic_id;
  uint32_t ring_id;

  // validate it's a proper ANIC device name, extract anic_id and ring_id;
  *is_ours = l_anicgetids(device, &anic_id, &ring_id);
  if (!*is_ours) {
    return NULL;
  }

  p = pcap_create_common(ebuf, sizeof(*rp));
  if (p == NULL) {
    fprintf(stderr, "anic: pcap_create_common() failed\n");
    return NULL;
  }
  p->activate_op = anic_activate;

  // minimal private data initialization, the real work is deferred to anic_activate()
  rp = (struct ring_s *)p->priv;
  memset(rp, 0, sizeof(*rp));
  rp->anic_id = anic_id;
  rp->ring_id = ring_id;

  return p;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_activate(pcap_t *p)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;
//struct card_s *c_p = (struct card_s *)&l_shp[r_p->anic_id];
  int tmp;
  char *s;

  if (1) {
    // in MFL mode, every ring stream uses a different ANIC handle
    r_p->anic_handle = anic_open("/dev/anic", r_p->anic_id);
    if (anic_error_code(r_p->anic_handle) != ANIC_ERR_NONE) {
      anic_close(r_p->anic_handle);
      goto fail;
    }

    // set ring freelist tag association
    anic_block_set_ring_nodetag(r_p->anic_handle, r_p->ring_id, r_p->ring_id);

    // determine number of blocks to use for ring
    r_p->blk_count = ANIC_RING_BLOCKS_DEFAULT;
    if ((s = getenv("ANIC_RING_BLOCKS")) != NULL) {
      tmp = atoi(s);
      if (tmp < 2 || tmp > 2047) {
        pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
          "anic_activate(anic:%u@%u): invalid ANIC_RING_BLOCKS value (%d) in environment",
          r_p->anic_id, r_p->ring_id, tmp);
        goto fail;
      }
    }

    // load blocks to free list for ring
    int blk;
    int bufid;
    void *v_p;
    struct anic_dma_info dma_info;
    int shmid;
    for (bufid = 0; bufid < r_p->blk_count; bufid++) {
      v_p = mmap(0, HUGEPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
      if (v_p == MAP_FAILED) {
        pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
          "anic_activate(anic:%u@%u): mmap() failure error %u %s",
          r_p->anic_id, r_p->ring_id, errno, strerror(errno));
        goto fail;
      }
      dma_info.userVirtualAddress = v_p;
      dma_info.length = HUGEPAGE_SIZE;
      dma_info.pageShift = ANIC_2M_PAGE;
      if (anic_map_dma(r_p->anic_handle, &dma_info)) {
        pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
          "anic_activate(anic:%u@%u): anic_map_dma() failed",
          r_p->anic_id, r_p->ring_id);
        goto fail;
      }
      blk = anic_block_add(r_p->anic_handle, r_p->ring_id, 0, r_p->ring_id, dma_info.dmaPhysicalAddress);
      if (blk < 0) {
        pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
          "anic_activate(anic:%u@%u): anic_block_add(bufid:%u) failed",
          r_p->anic_id, r_p->ring_id, bufid);
        goto fail;
      }
      r_p->blk_buf[blk] = (uint8_t *)v_p;
      r_p->blk_dma[blk] = dma_info.dmaPhysicalAddress;
    }
  } else {
    // not supporting non-MFL for now
    goto fail;
  }

  // enable ring
  anic_block_ena_ring(r_p->anic_handle, r_p->ring_id, 1);

  // set callbacks and return success
  p->selectable_fd - -1;
  p->linktype = DLT_EN10MB;
  p->read_op = anic_read;
  p->inject_op = anic_inject;
  p->setfilter_op = anic_setfilter;
  p->setdirection_op = NULL;
  p->set_datalink_op = anic_set_datalink;
  p->getnonblock_op = anic_getnonblock;
  p->setnonblock_op = anic_setnonblock;
  p->stats_op = anic_stats;
  p->cleanup_op = anic_cleanup;
  return 0;

fail:
  pcap_cleanup_live_common(p);
  return PCAP_ERROR;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;
  int n;
  uint32_t blkcnt;

  n = 0;
  while (n < cnt || PACKET_COUNT_IS_UNLIMITED(cnt)) {
    // has pcap_breakloop() been called?
    if (p->break_loop) {
      if (n == 0) {
        p->break_loop = 0;
        return -2;
      } else {
        return n;
      }
    }

    if (r_p->blk_valid && r_p->buf_p > r_p->last_p) {
      // return prior block to freelist when finished
      int blk_tmp;
      r_p->blk_valid = 0;
      blk_tmp = anic_block_add(r_p->anic_handle, r_p->ring_id, 0, r_p->ring_id, r_p->blk_dma[r_p->blk_id]);
      if (blk_tmp < 0) {
        fprintf(stderr, "anic_block_add(ring:%u) failed\n", r_p->ring_id);
        abort();
      }
      if (r_p->blk_buf[blk_tmp] != NULL) {
      }
      r_p->blk_buf[blk_tmp] = r_p->blk_buf[r_p->blk_id];
      r_p->blk_dma[blk_tmp] = r_p->blk_dma[r_p->blk_id];
      if (blk_tmp != r_p->blk_id)
        r_p->blk_buf[r_p->blk_id] = NULL;
    }

    if (!r_p->blk_valid) {
      // get a new block
      struct anic_blkstatus_s blkstatus;
      uint32_t cnt;

      blkcnt = anic_block_get(r_p->anic_handle, r_p->ring_id, r_p->ring_id, &blkstatus);
      if (blkcnt == 0)
        return n;
      r_p->blk_id = blkstatus.blkid;
      if (r_p->blk_buf[blkstatus.blkid] == NULL) {
        fprintf(stderr, "anic_block_get(ring:%u) returned invalid blkid:%u\n", r_p->ring_id, blkstatus.blkid);
        abort();
      }
      r_p->buf_p = r_p->blk_buf[blkstatus.blkid] + blkstatus.firstpkt_offset;
      r_p->last_p = r_p->blk_buf[blkstatus.blkid] + blkstatus.lastpkt_offset;
      r_p->blk_valid = 1;
    }

    struct anic_descriptor_rx_packet_data *desc_p;
    uint8_t *pktaddr;
    uint32_t caplen;
    struct pcap_pkthdr hdr;

    desc_p = (struct anic_descriptor_rx_packet_data *)r_p->buf_p;
    pktaddr = (uint8_t *)&desc_p[1]; 
    r_p->buf_p += (desc_p->length + 7) & ~7;
    r_p->packets++;
    caplen = desc_p->length - sizeof(*desc_p);
    if (caplen > p->snapshot)
      caplen = p->snapshot;
    if (p->fcode.bf_insns == NULL || 
        bpf_filter(p->fcode.bf_insns, pktaddr, desc_p->origlength, caplen)) {
      hdr.ts.tv_sec = desc_p->timestamp >> 32;
      hdr.ts.tv_usec = ((desc_p->timestamp & 0xffffffff) * 1000000) >> 32;
      hdr.caplen = caplen;
      hdr.len = desc_p->origlength;
      callback(user, &hdr, pktaddr);
      n++;
    }
  }
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_inject(pcap_t *p, const void *buf _U_, size_t size _U_)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;

  pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
    "anic_inject(anic:%u@%u) sending packets isn't supported on ANIC cards through libpcap",
    r_p->anic_id, r_p->ring_id);
  return -1;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_setfilter(pcap_t *p, struct bpf_program *fp)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;

  if (!fp) {
    pcap_snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
      "anic_setfilter(anic:%u@%u) no filter specified",
      r_p->anic_id, r_p->ring_id);
    return -1;
  }

  // private copy of filter
  if (install_bpf_program(p, fp) < 0)
    return -1;

  return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_set_datalink(pcap_t *p, int dlt)
{
  p->linktype = dlt;
  return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_getnonblock(pcap_t *p, char *errbuf)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;
  return r_p->nonblocking;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;
  r_p->nonblocking = nonblock;
  return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int anic_stats(pcap_t *p, struct pcap_stat *ps)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;
  struct anic_rx_xge_counts_all all;
  uint64_t total = 0L;
  uint32_t port;

  anic_port_get_counts_all(r_p->anic_handle, 1, &all);
//for (port = 0; port < r_p->port_count; port++)
  for (port = 0; port < 2; port++)   // TBD
    total += all.counts[port].rsrcs;
  ps->ps_recv = r_p->packets;
  ps->ps_drop = anic_block_get_ring_dropcount(r_p->anic_handle, r_p->ring_id);
  ps->ps_ifdrop = total & 0xffffffff;
  return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static void anic_cleanup(pcap_t *p)
{
  struct ring_s *r_p = (struct ring_s *)p->priv;

  // TBD
  pcap_cleanup_live_common(p);
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
static int l_anicgetids(const char *devname, uint32_t *anic_id, uint32_t *ring_id)
{
  char tmpstr[5];
  int tmp;

  strncpy(tmpstr, devname, 4);
  tmpstr[5] = '\0';
  // not an ANIC, return with no message
  if (strcmp(tmpstr, "anic") != 0)
    return 0;

  if (   !devname[4] || devname[4] != ':'
      || !devname[5] || devname[5] < '0' || (devname[5] >= '0' + MAX_ANICS)
      || !devname[6] || devname[6] != '@'
      || !devname[7])
    goto errorreturn;
  *anic_id = devname[5] - '0';
  strncpy(tmpstr, &devname[7], 2);
  tmpstr[2] = '\0';
  tmp = atoi(tmpstr);
  if (tmp >= MAX_RINGS)
    goto errorreturn;
  *ring_id = tmp;
  return 1;

errorreturn:
  fprintf(stderr, "anic: invalid device name \"%s\"\n", devname);
  fprintf(stderr, "  device names must be of the form \"anic:<anic_id>@<ring_id>\"\n");
  fprintf(stderr, "  where anic_id is in the range 0 to %d and rind_id is in the range 0 to %d\n", MAX_ANICS, MAX_RINGS);
  return 0;
}

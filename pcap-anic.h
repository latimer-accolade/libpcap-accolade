/*
 * pcap-anic.h: Packet capture interface for Accolade ANIC card.
 *
 * Author: Robert Latimer (latimer@accoladetechnology.com)
 */

extern pcap_t *anic_create(const char *device, char *ebuf, int *is_ours);
extern int anic_findalldevs(pcap_if_t **devlistp, char *errbuf);

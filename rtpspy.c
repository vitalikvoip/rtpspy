/*
 * rtpspy.c
 *
 *  Created on: Jan 9, 2015
 *      Author: vitalik
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <pcap.h>
#include <time.h>

/* Network headers */
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "config.h"
#include "stream_table.h"
#include "rtp.h"
#include "logger.h"

#define DLT_LINUX_SSL 113

static uint8_t running      = 1;

static void sig_handler(int sig, siginfo_t *siginfo, void *ctx);
static int  init_signals(void);

static void sig_handler(int sig, siginfo_t *siginfo, void *ctx)
{
	log_error("Got signal [%d], code [%d]", sig, (int)siginfo->si_code);
	running = 0;
}

static int init_signals(void)
{
	struct sigaction act;
	int rc = -1;

	memset(&act, 0, sizeof(act));

	act.sa_sigaction = sig_handler;
	act.sa_flags     = SA_RESTART | SA_SIGINFO;

	do {
		if (sigaction(SIGTERM, &act, NULL) < 0)
			break;
		if (sigaction(SIGINT, &act, NULL) < 0)
			break;

		rc = 0;
	} while(0);

	return rc;
}

static ssize_t parse_cmdline(int ac, char **av, cfg_t *cfg)
{
	int c = 0;
	int opt_idx = 0;
	int err = 0;
	int tmp = 0;

	static struct option long_options[] =
	{
		 {"interface",      required_argument, 0, 'i'}
		,{"file",           required_argument, 0, 'F'}
		,{"dir",            required_argument, 0, 'd'}
		,{"filter",         required_argument, 0, 'f'}
		,{"stream_tout",    required_argument, 0, 't'}
		,{"cleanup_period", required_argument, 0, 'T'}
		,{"table_size",     required_argument, 0, 's'}
		,{0,0,0,0}
	};

	while (1)
	{
		c = getopt_long(ac, av, "i:F:d:f:t:T:s:", long_options, &opt_idx);

		if (-1 == c)
			break;

		switch(c)
		{
		case 'i':
			if (cfg->mode == MOD_NONE)
			{
				cfg->mode  = MOD_LIVE;
				cfg->iface = optarg;
			}
			else
			{
				log_error("Choose only LIVE or OFFLINE mode");
				err++;
			}
			break;
		case 'F':
			if (cfg->mode == MOD_NONE)
			{
				cfg->mode    = MOD_OFFLINE;
				cfg->in_file = optarg;
			}
			else
			{
				log_error("Choose only LIVE or OFFLINE mode");
				err++;
			}
			break;
		case 'd':
			cfg->dump_dir = optarg;
			break;
		case 'f':
			cfg->filter = optarg;
			break;
		case 't':
			cfg->stream_timeout = atoi(optarg);
			break;
		case 'T':
			cfg->cleanup_period = atoi(optarg);
			break;
		case 's':
			tmp = atoi(optarg);
			if (tmp > 0 && tmp <= 15)
				cfg->stream_tbl_size = 2 << tmp;
			break;
		default:
			err++;
			break;
		}

		if (err)
			break;
	}

	if (MOD_NONE == cfg->mode)
	{
		err++;
		log_error("Traffic source is not selected");
	}

	if (err)
		return -1;

	return 0;
}

static pcap_t *open_pcap_stream(cfg_t *cfg, char *errbuf)
{
	pcap_t *handle = NULL;
	char               err[BUFSIZ];
	struct bpf_program pcap_filter;

	if (!cfg)
		return NULL;

	memset(err, 0, sizeof(err));
	memset(&pcap_filter, 0, sizeof(pcap_filter));

	do {
		/* Open stream */
		switch(cfg->mode) {
		case MOD_OFFLINE:
			handle = pcap_open_offline(cfg->in_file, errbuf);
			snprintf(err, sizeof(err), "Error oppeninig dump file: %s", cfg->in_file);
			break;
		case MOD_LIVE:
			handle = pcap_open_live(cfg->iface, 0xFFFF, cfg->promisc, 1000 * cfg->sniff_timeout, errbuf);
			snprintf(err, sizeof(err), "Error opening interface: %s", cfg->iface);
			break;
		default:
			break;
		}

		if (!handle)
		{
			log_error("%s", err);
			break;
		}

		log_debug("Compiling filter: %s", cfg->filter);

		/* Compile filter */
		if (pcap_compile(handle, &pcap_filter, cfg->filter, 0, PCAP_NETMASK_UNKNOWN) < 0)
		{
			log_error("Couldn't parse filter %s: %s", cfg->filter, pcap_geterr(handle));
			break;
		}

		/* Apply filter */
		if (pcap_setfilter(handle, &pcap_filter) == -1)
		{
			log_error("Couldn't install filter %s: %s", cfg->filter, pcap_geterr(handle));
			pcap_freecode(&pcap_filter);
			break;
		}

		pcap_freecode(&pcap_filter);

		return handle;
	} while(0);

	if (handle)
		pcap_close(handle);

	return NULL;
}

typedef void (*packet_cb_fn)(struct pcap_pkthdr *pcap_hdr, const uint8_t *data, size_t offset_to_ip, void *stream_table);

static void process_pcap_stream(pcap_t *pcap, packet_cb_fn read_cb, cfg_t *cfg, void *stream_table)
{
	int    datalink_type = 0;   /* Link type */
	size_t offset_to_ip  = 0;	/* Datalink hdr size */
	size_t err           = 0;

	struct pcap_pkthdr *pcap_hdr = NULL;   /* header that pcap gives us */
	const uint8_t *raw_packet    = NULL;

	datalink_type = pcap_datalink(pcap);
	switch (datalink_type) {
	case DLT_EN10MB:
		offset_to_ip = sizeof(struct ethhdr);
		break;
	case DLT_LINUX_SSL:
		offset_to_ip = 16;
		break;
	case DLT_RAW:
		offset_to_ip = 0;
		break;
	default:
		log_error("Unknown interface type: %d", datalink_type);
		err++;
		break;
	}

	if (err)
		return;

	while(running)
	{
		int pcap_rc = 0;

		pcap_rc = pcap_next_ex(pcap, &pcap_hdr, &raw_packet);
		if (1 == pcap_rc)
		{
			/* packet received */
			read_cb(pcap_hdr, raw_packet, offset_to_ip, stream_table);

			stream_tbl_timer(stream_table, pcap_hdr->ts.tv_sec);
		}
		else if (-1 == pcap_rc)
		{
			/* read error */
			log_error("pcap_next_ex rc: %d, error: %s", pcap_rc, pcap_geterr(pcap));
			break;
		}
		else if (-2 == pcap_rc)
		{
			/* EOF */
			log_error("End of file: %s", cfg->in_file);
			break;
		}
		else if (0 == pcap_rc && MOD_LIVE == cfg->mode)
		{
			/* read timeout */
			stream_tbl_timer(stream_table, time(NULL));
		}

	}

	return;
}

static void dump_rtp_packet(rtp_t *rtp, struct timeval *ts)
{
	log_debug_hi("RTP SSRC [ %#12x ] seq [ %3lu ] p [%d] x[%d] cc [%d] m [%d] pt [%d] packet timestamp [%ld]",
			ntohl(rtp->ssrc),
			(long unsigned)ntohs(rtp->seq),
			rtp->p,
			rtp->x,
			rtp->cc,
			rtp->m,
			rtp->pt,
			ts->tv_sec);
}

static void process_rtp_packet(struct pcap_pkthdr *pcap_hdr, const uint8_t *data, size_t offset_to_ip, void *stream_table)
{
#define OFFSET_TO_UDP_DATA (sizeof(struct iphdr) + sizeof(struct udphdr))
#define MIN_RTP_PACKET     (OFFSET_TO_UDP_DATA + sizeof(rtp_t))
#define MIN_RTCP_PACKET    (OFFSET_TO_UDP_DATA + sizeof(rtcp_t))

	struct iphdr   *ip   = NULL;
	struct udphdr  *udp  = NULL;
	rtp_t  *rtp  = NULL;
	rtcp_t *rtcp = NULL;

	do {
		/* skip too short IP packets */
		if (pcap_hdr->caplen < (offset_to_ip + sizeof(*ip)))
			break;

		ip = (struct iphdr*)((uint8_t*)data + offset_to_ip);
		if (4 != ip->version)
			break;

		log_debug_hi("IP packet with proto [ %d ], len [ %d ]", ip->protocol, ntohs(ip->tot_len));

		/* skip non UDP */
		if (IPPROTO_UDP != ip->protocol)
			break;

		/* skip too short UDP datagrams */
		if (pcap_hdr->caplen < (offset_to_ip + sizeof(*ip) + sizeof(*udp)))
			break;

		udp = (struct udphdr*)((uint8_t*)data + offset_to_ip + sizeof(*ip));

		log_debug_hi("UDP src port [ %d ] dst port [ %d ]", ntohs(udp->source), ntohs(udp->dest));

		if (pcap_hdr->caplen < (offset_to_ip + MIN_RTP_PACKET))
			break;

		rtp =  (rtp_t *) ((uint8_t*)data + offset_to_ip + OFFSET_TO_UDP_DATA);
		if (pcap_hdr->caplen >= MIN_RTCP_PACKET)
			rtcp = (rtcp_t *)((uint8_t*)data + offset_to_ip +OFFSET_TO_UDP_DATA);

		/* skip non rtp&rtcp packets */
		if (RTP_VERSION != rtp->version)
			break;

		if ((PT_PCMU != rtp->pt && PT_GSM  != rtp->pt && PT_G723 != rtp->pt &&
		     PT_PCMA != rtp->pt && PT_G722 != rtp->pt && PT_G729 != rtp->pt))
			break;

		if (0 != rtp->cc &&
		    0 != rtp->x  &&
		    0 != rtp->m)
			break;

		struct sockaddr_in src;
		struct sockaddr_in dst;

		src.sin_family      = AF_INET;
		src.sin_port        = udp->source;
		src.sin_addr.s_addr = ip->saddr;

		dst.sin_family      = AF_INET;
		dst.sin_port        = udp->dest;
		dst.sin_addr.s_addr = ip->daddr;

		stream_t *stream = stream_tbl_get_stream(stream_table, ntohl(rtp->ssrc), &src, &dst, pcap_hdr->ts.tv_sec);
		if (!stream)
			break;

		if (stream_add_packet(stream, ntohs(rtp->seq), rtp->pt, ntohl(rtp->ts), pcap_hdr->ts.tv_sec) < 0)
		{
			log_error("error adding a packet to a stream [%p]", stream);
			break;
		}
	} while(0);

	return;
}

int main(int ac, char *av[])
{
	char errbuf[PCAP_ERRBUF_SIZE];         /* error buffer */
	pcap_t *pcap_handler   = NULL;         /* Session handler */
	int exit_code       = EXIT_SUCCESS;

	cfg_t *cfg = config_create();
	if (!cfg)
		exit(EXIT_FAILURE);

	if (parse_cmdline(ac, av, cfg) < 0)
	{
		exit_code = EXIT_FAILURE;
		goto exit;
	}

	/* init signals */
	if (init_signals() < 0)
	{
		log_error("signals error");
		exit_code = EXIT_FAILURE;
		goto exit;
	}

	pcap_handler = open_pcap_stream(cfg, errbuf);
	if (!pcap_handler)
	{
		exit_code = EXIT_FAILURE;
		goto exit;
	}

	/* create stream table */
	stream_tbl_t *tbl = stream_tbl_create(cfg->stream_tbl_size, cfg->stream_timeout, cfg->cleanup_period, cfg->dump_dir);
	if (!tbl)
	{
		exit_code = EXIT_FAILURE;
		goto exit;
	}

	process_pcap_stream(pcap_handler, process_rtp_packet, cfg, tbl);

exit:
	if (pcap_handler)
		pcap_close(pcap_handler);

	if (cfg)
		config_destroy(cfg);

	if (tbl)
		stream_tbl_destroy(tbl);

	return exit_code;
}

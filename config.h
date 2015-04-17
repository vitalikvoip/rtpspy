/*
 * config.h
 *
 *  Created on: Jan 13, 2015
 *      Author: vitalik
 */

#ifndef __RTPSPY_CONFIG_H__
#define __RTPSPY_CONFIG_H__

/* forward declaration */
typedef struct rtpspy_config cfg_t;
typedef enum   rtpspy_mode   spy_mode_t;

#define DEF_DUMP_DIR      "/var/spool/rtpspy"
#define DEF_IFACE         "eth0"
#define DEF_INFILE        ""
#define DEF_FILTER        "udp"
#define SNIFF_TIMEOUT     5       /* sec */
#define STREAM_TIMEOUT    30      /* sec */
#define CLEANUP_PERIOD    10      /* sec */
#define STREAM_TBL_SIZE   1024    /* 2^x */

/*
 * \brief rtp spy application sniffing modes
 */
enum rtpspy_mode
{
	MOD_OFFLINE
	,MOD_LIVE
	,MOD_NONE
};

/*
 * \brief rtp spy application config
 */
struct rtpspy_config
{
	char       *dump_dir;
	char       *filter;
	char       *iface;
	char       *in_file;
	spy_mode_t  mode;
	size_t      sniff_timeout;
	time_t      stream_timeout;
	time_t      cleanup_period;
	size_t      stream_tbl_size;
	uint8_t     promisc;
};


/*
 * \brief Config constructor
 */
cfg_t *config_create(void);

/*
 * \brief Config destructor
 */
void   config_destroy(cfg_t *);

#endif /* __RTPSPY_CONFIG_H__ */

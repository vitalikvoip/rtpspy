/*
 * config.c
 *
 *  Created on: Jan 13, 2015
 *      Author: vitalik
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "config.h"

cfg_t *config_create(void)
{
	cfg_t *obj = NULL;

	do {
		obj = calloc(1, sizeof(*obj));
		if (!obj)
			break;

		memset(obj, 0, sizeof(*obj));

		obj->dump_dir        = DEF_DUMP_DIR;
		obj->filter          = DEF_FILTER;
		obj->iface           = DEF_IFACE;
		obj->in_file         = DEF_INFILE;
		obj->mode            = MOD_NONE;
		obj->filter          = DEF_FILTER;
		obj->sniff_timeout   = SNIFF_TIMEOUT;
		obj->stream_timeout  = STREAM_TIMEOUT;
		obj->cleanup_period  = CLEANUP_PERIOD;
		obj->stream_tbl_size = STREAM_TBL_SIZE;

		return obj;
	} while(0);

	if (obj)
		free(obj);

	return NULL;
}

void config_destroy(cfg_t *obj)
{
	if (!obj)
		return;

	free(obj);
}

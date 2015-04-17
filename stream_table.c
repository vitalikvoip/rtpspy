/*
 * StreamTable.c
 *
 *  Created on: Jan 12, 2015
 *      Author: vitalik
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pcap.h>

#include <time.h>

#include "rtp.h"
#include "stream_table.h"
#include "hashmap.h"
#include "logger.h"

struct stream_struct
{
	uint32_t            ssrc;
	struct sockaddr_in *src;
	struct sockaddr_in *dst;
	char               *str_src;
	char               *str_dst;

	char               *id;
	char               *fname; /* id.pcap */
	FILE               *dump;

	uint32_t            frames_num;
	uint32_t            ts_first; // TODO
	uint32_t            ts_last;  // TODO

	time_t              created;
	time_t              updated;
};

struct stream_table_struct
{
	map_t  map;              /* stream container                   */
	time_t timer_last;       /* timestamp of the last timer call   */
	time_t stream_timeout;   /* timeout for each rtp stream        */
	time_t cleanup_period;   /* table cleanup period               */

	char   *dir;            /* directory for dumps and index file */
};

typedef struct timer_param
{
	stream_tbl_t *tbl;
	time_t        current;
} timer_param_t;

//------------------------------------------------------------------------------
// tools
//------------------------------------------------------------------------------
static struct sockaddr_in *copy_sockaddrin(const struct sockaddr_in *addr)
{
	struct sockaddr_in *copy = NULL;

	do {
		if (!addr)
			break;

		copy = calloc(1, sizeof(*copy));
		if (!copy)
			break;

		memcpy(copy, addr, sizeof(*copy));

		return copy;
	} while(0);

	return NULL;
}
static void print_addr(const struct sockaddr_in *addr, char *buf, size_t size)
{
	char host[100];
	char port[10];

	memset(host,0,sizeof(host));
	memset(port,0,sizeof(port));

	if (getnameinfo((struct sockaddr*)addr, sizeof(*addr), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST|NI_NUMERICSERV) < 0)
		return;

	snprintf(buf, size, "%s_%s", host, port);

	return;
}

static ssize_t gen_stream_id(uint32_t ssrc, char *src, char *dst, char *buf, size_t size)
{
	if (!ssrc || !src || !dst || !buf || !size)
		return -1;

	snprintf(buf, size, "%#lx_%s_%s", (long unsigned)ssrc, src, dst);
	return 0;
}

//-----------------------------------------------------------------------------
// stream implementation
//-----------------------------------------------------------------------------
stream_t *stream_create(uint32_t ssrc,
                        const struct sockaddr_in *src,
                        const struct sockaddr_in *dst,
                        const char *dir,
                        time_t pcap_time)
{
	stream_t *obj = NULL;
	char buf[BUFSIZ];

	/*  _________________________________________________________
	 * | version = 1 | ssrc   | number of packets | other data   |
	 * |     16bit   | 32bit  |        32bit      |  80bits      |
	 *  _________________________________________________________
	 * |                  160bit == 20bytes                      |
	 */
	uint8_t header[20];
	uint16_t short_var=0;
	uint32_t long_var=0;

	do {
		if (!ssrc || !src || !dst)
			break;

		obj = calloc(1, sizeof(*obj));
		if (!obj)
			break;

		/* ssrc, src, dst */
		obj->ssrc = ssrc;
		obj->src  = copy_sockaddrin(src);
		obj->dst  = copy_sockaddrin(dst);

		/* str_src */
		print_addr(src, buf, sizeof(buf));
		obj->str_src = strdup(buf);

		/* src_dst */
		print_addr(dst, buf, sizeof(buf));
		obj->str_dst = strdup(buf);

		/* stream_id */
		memset(buf, 0, sizeof(buf));
		gen_stream_id(obj->ssrc, obj->str_src, obj->str_dst, buf, sizeof(buf));
		obj->id = strdup(buf);

		/* dump filename */
		memset(buf, 0, sizeof(buf));

		if (dir && strlen(dir))
			snprintf(buf, sizeof(buf), "%s/%s.dump", dir, obj->id);
		else
			snprintf(buf, sizeof(buf), "%s.dump", obj->id);

		obj->fname = strdup(buf);

		/* dump I/O  */
		obj->dump = fopen(obj->fname, "w");
		if (!obj->dump)
			break;

		/* write a dump header */
		memset(header, 0, sizeof(header));

		short_var = htons(1);
		memcpy(header, &short_var, sizeof(short_var));
		long_var = htonl(obj->ssrc);
		memcpy(header + 2, &long_var, sizeof(long_var));

		fwrite(&header, sizeof(header), 1, obj->dump);

		obj->created = pcap_time;
		obj->updated = pcap_time;

		return obj;
	} while(0);

	if (obj)
	{
		if (obj->src)
			free(obj->src);
		if (obj->dst)
			free(obj->dst);
		if (obj->str_src)
			free(obj->str_src);
		if (obj->str_dst)
			free(obj->str_dst);
		if (obj->id)
			free(obj->id);
		if (obj->fname)
			free(obj->fname);
		if (obj->dump)
			fclose(obj->dump);
	}

	return NULL;
}

ssize_t stream_add_packet(stream_t *stream, uint16_t seq, uint8_t pt, uint32_t timestamp, time_t pcap_time)
{
	uint32_t long_var  = 0;
	uint16_t short_var = 0;

	do {
		if (!stream)
			break;

		/*	all data is in network byte order:
		 *
		 * 	| timestamp  | seq   | pt   | padding |
		 *  | 32bit      | 16bit | 8bit | 8bit    |
		 */

		/* timestamp */
		long_var = htonl(timestamp);
		fwrite(&long_var, sizeof(long_var), 1, stream->dump);

		/* seq */
		short_var = htons(seq);
		fwrite(&short_var, sizeof(short_var), 1, stream->dump);

		/* pt */
		fwrite(&pt, sizeof(pt), 1, stream->dump);

		/* just a 1 byte padding to alling data to 32bit boundaries */
		fwrite(&pt, sizeof(pt), 1, stream->dump);

		stream->updated = pcap_time;
		stream->frames_num++;

		return 0;
	} while(0);

	return -1;
}

void stream_destroy(stream_t *obj)
{
	uint32_t long_var=0;

	if (!obj)
		return;

	log_notice("closing stream [ %#12x ] duration [%d sec] frames [%lu] from [%s] to [%s]",
			obj->ssrc,
			(int)(obj->updated - obj->created),
			(long unsigned)obj->frames_num,
			obj->str_src, obj->str_dst);

	if (obj->src)
		free(obj->src);
	if (obj->dst)
		free(obj->dst);
	if (obj->str_src)
		free(obj->str_src);
	if (obj->str_dst)
		free(obj->str_dst);
	if (obj->id)
		free(obj->id);
	if (obj->fname)
		free(obj->fname);
	if (obj->dump)
	{
		// update dump header
		fseek(obj->dump, 6, SEEK_SET);

		long_var = htonl(obj->frames_num);
		fwrite(&long_var, sizeof(long_var), 1, obj->dump);

		fflush(obj->dump);
		fclose(obj->dump);
	}

	free(obj);
}

static int stream_timer(void *ctx, void *data)
{
	timer_param_t *param  = (timer_param_t*)ctx;
	stream_t      *stream = (stream_t*)data;

	if (!param || !stream)
		return MAP_MISSING;

	if ( (param->current - stream->updated) >= param->tbl->stream_timeout)
	{
		char *id = strdup(stream->id);

		/* close stream */
		if (hashmap_remove(param->tbl->map, stream->id) != MAP_OK)
			log_error("failed to remove stream: %s", id);

		free(id);
	}

	return MAP_OK;
}

//-----------------------------------------------------------------------------
// stream table implementation
//-----------------------------------------------------------------------------
stream_tbl_t *stream_tbl_create(size_t size, time_t stream_timeout, time_t cleanup_period, char *dump_dir)
{
	stream_tbl_t *obj = NULL;

	do {
		obj = calloc(1, sizeof(*obj));
		if (!obj)
			break;

		obj->map = hashmap_new(size, (PFdestroy)stream_destroy);
		if (!obj->map)
			break;

		obj->timer_last     = 0;
		obj->stream_timeout = stream_timeout;
		obj->cleanup_period = cleanup_period;
		obj->dir            = ( dump_dir && strlen(dump_dir) ) ?  strdup(dump_dir) : "";

		log_notice("Table %p created", obj);

		return obj;
	} while(0);

	if (obj)
	{
		if (obj->map)
			hashmap_free(obj->map);
		free(obj);
	}

	return NULL;
}

void stream_tbl_destroy(stream_tbl_t *obj)
{
	if (!obj)
		return;

	if (obj->dir)
		free(obj->dir);

	if (obj->map)
	{
		hashmap_clear(obj->map);
		hashmap_free(obj->map);
	}

	free(obj);

	log_notice("Table %p destroyed", obj);
}

ssize_t stream_tbl_add_stream(stream_tbl_t *tbl, stream_t *stream)
{
	do {
		if (!tbl || !stream)
			break;

		if (!stream->str_src || !stream->str_dst)
			break;

		if (hashmap_put(tbl->map, stream->id, stream) != MAP_OK)
			break;

		return 0;
	} while(0);

	return -1;
}

stream_t *stream_tbl_get_stream(stream_tbl_t *tbl, uint32_t ssrc,
		const struct sockaddr_in *src, const struct sockaddr_in *dst,
		time_t curr_time)
{
	char id_buf[BUFSIZ];
	char src_buf[BUFSIZ];
	char dst_buf[BUFSIZ];

	stream_t *stream = NULL;

	do {
		if (!tbl || !ssrc || !src || !dst)
			break;

		memset(id_buf,  0, sizeof(id_buf));
		memset(src_buf, 0, sizeof(src_buf));
		memset(dst_buf, 0, sizeof(dst_buf));

		print_addr(src, src_buf, sizeof(src_buf));
		print_addr(dst, dst_buf, sizeof(dst_buf));

		gen_stream_id(ssrc, src_buf, dst_buf, id_buf, sizeof(id_buf));

		if (MAP_OK != hashmap_get(tbl->map, id_buf, (void**)&stream))
		{
			log_debug("stream [%s] is not found", id_buf);

			stream = stream_create(ssrc, src, dst, tbl->dir, curr_time);
			if (!stream)
				break;

			log_notice("stream [ %65s ] adding a new stream", id_buf);

			if (hashmap_put(tbl->map, stream->id, stream) != MAP_OK)
			{
				log_error("Error adding a new stream [ %s ]", id_buf);
				stream_destroy(stream);
				break;
			}
		}

		return stream;
	} while(0);

	return NULL;
}

void stream_tbl_timer(stream_tbl_t *tbl, time_t current)
{
	do {
		if (!tbl)
			return;

		if (tbl->cleanup_period > (current - tbl->timer_last))
			break;

		tbl->timer_last = current;

		{
			struct tm* tm_info = NULL;
			char time_str[BUFSIZ];

			tm_info = localtime(&current);
			strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

			log_debug("stream table timer event: %s", time_str);
		}

		timer_param_t *param = calloc(1, sizeof(timer_param_t));
		if (!param)
			break;

		param->tbl     = tbl;
		param->current = current;

		hashmap_iterate(tbl->map, stream_timer, param);

		free(param);

	} while(0);
}

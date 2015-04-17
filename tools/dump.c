#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define FRAME_SIZE 8

typedef struct rtp_header {
	uint32_t ts;
	uint16_t seq;
	uint8_t  pt;
} rtp_frame_t;

typedef struct stream {
	uint32_t      ssrc;
	uint32_t      ts_first;
	uint32_t      ts_last;
	rtp_frame_t  *packets;
	size_t        packets_num;
} rtp_stream_t;

static rtp_stream_t *stream_create(uint32_t, size_t);
static void          stream_destroy(rtp_stream_t*);

static rtp_stream_t *stream_create(uint32_t ssrc, size_t frames_count)
{
	rtp_stream_t *stream = NULL;

	do {
		if (!frames_count)
			break;

		stream = calloc(1, sizeof(rtp_stream_t));
		if (!stream)
			break;

		stream->packets = calloc(frames_count, sizeof(rtp_frame_t));
		if (!stream->packets)
			break;

		stream->ssrc        = ssrc;
		stream->packets_num = frames_count;

		return stream;
	} while(0);

	stream_destroy(stream);

	return NULL;
}

static void stream_destroy(rtp_stream_t *obj)
{
	if (!obj)
		return;

	if (obj->packets)
		free(obj->packets);
	free(obj);

	return;
}

static rtp_stream_t *load_stream(const char *fname)
{
	FILE     *dump = NULL;
	uint32_t  frames_count = 0;
	uint32_t  ssrc=0;
	uint16_t  version=0;

	uint32_t  long_var=0;
	uint16_t  short_var=0;

	size_t    err=0;

	dump = fopen(fname, "r");
	if (!dump) {
		fprintf(stderr, "can't open the file: %s\n", fname);
		err++;
		goto finish;
	}

	/* process header */
	fread(&short_var, sizeof(short_var), 1, dump);
	version = ntohs(short_var);

	if (1 != version)
	{
		fprintf(stderr, "stream [ %s ] has a wrong version number [ %d ]\n", fname, version);
		err++;
		goto finish;
	}

	fread(&long_var, sizeof(long_var), 1, dump);
	ssrc = ntohl(long_var);

	fread(&long_var, sizeof(long_var), 1, dump);
	frames_count = ntohl(long_var);

	printf("Opening stream [ %s ] ver [%d] ssrc [ %#lx ] packets [ %zu ]\n",
			fname, version, (long unsigned)ssrc, (size_t)frames_count);

	fseek(dump, 20, SEEK_SET);

	rtp_stream_t *stream = stream_create(ssrc, frames_count);
	if (!stream)
	{
		fprintf(stderr, "can't allocate stream\n");
		err++;
		goto finish;
	}

	size_t i;
	for (i = 0; i < stream->packets_num; i++)
	{
		uint8_t  buf[FRAME_SIZE];
		uint32_t ts   = 0;
		uint16_t seq  = 0;
		uint8_t  pt   = 0;

		int n = 0;
		memset(&buf, 0, sizeof(buf));

		n = fread(buf, 1, sizeof(buf), dump);
		if (FRAME_SIZE != n)
		{
			if (ferror(dump))
				fprintf(stderr, "ERROR\n");
			else
				fprintf(stderr, "To short dump\n");

			err++;
			break;
		}

		/*	all data is in network byte order:
		 *
		 * 	| timestamp  | seq   | pt   | padding |
		 *  | 32bit      | 16bit | 8bit | 8bit    |
		 */

		memcpy(&ts  , buf    , 4);
		memcpy(&seq , buf + 4, 2);
		memcpy(&pt  , buf + 6, 1);

		ts   = ntohl(ts);
		seq  = ntohs(seq);

		stream->packets[i].ts   = ts;
		stream->packets[i].seq  = seq;
		stream->packets[i].pt   = pt;
	}

finish:
	fclose(dump);

	if (err)
	{
		stream_destroy(stream);
		return NULL;
	}
	else
		return stream;
}

static int compare_rtp_frame(const void *d1, const void *d2)
{
	rtp_frame_t *f1 = (rtp_frame_t *)d1;
	rtp_frame_t *f2 = (rtp_frame_t *)d2;

	if (f1->ts < f2->ts)
		return -1;
	else if (f1->ts == f2->ts)
		return 0;
	else
		return 1;
}

static int find_rtp_frame(rtp_stream_t *s, uint16_t seq, uint32_t ts)
{
	size_t first  = 0;
	size_t last   = s->packets_num - 1;
	size_t middle = (first + last) / 2;
	size_t found  = 0;

	while (first <= last)
	{
		if ( s->packets[middle].ts < ts)
			first = middle + 1;
		else if ( s->packets[middle].ts == ts)
			found++;
		else if (middle != 0)
			last = middle - 1;
		else
			break;

		if (found)
			break;

		middle = (first + last) / 2;
	}

	if (found)
		return 1;
	else
		return 0;
}

static void sort_stream(rtp_stream_t *s)
{
	qsort(s->packets, s->packets_num, sizeof(s->packets[0]), compare_rtp_frame);

	return;
}

static void compare_streams(rtp_stream_t *s1, rtp_stream_t *s2)
{
	size_t matched_cnt=0;
	float loss = 0;

	if (!s1 || !s2)
		return;

	size_t i=0;
	for (i=0; i < s1->packets_num; i++)
		if (find_rtp_frame(s2, s1->packets[i].seq, s1->packets[i].ts))
			matched_cnt++;

	loss = ( ((float)(s1->packets_num - matched_cnt)) / s1->packets_num ) * 100;

	printf("S1 has [ %zu ] frames, S2 has [ %zu ] frames, matched [ %zu ], packet loss [ %3.1f%% ]\n",
			s1->packets_num, s2->packets_num, matched_cnt, loss);
}

int main(int ac, char **av)
{
	int i;
	rtp_stream_t *streams[2] = {NULL, NULL};

	if (ac != 3) {
		fprintf(stderr, "Usage: ./dump filename1 [filename2]\n");
		return -1;
	}

	for (i = 1; i < ac; i++)
		streams[i-1] = load_stream(av[i]);

	if (streams[0] && streams[1])
	{
		printf("Got 2 streams for comparison\n");
		printf("SSRC [ %#lx ] packets [ %lu ]\n", (long unsigned)streams[0]->ssrc, streams[0]->packets_num);
		printf("SSRC [ %#lx ] packets [ %lu ]\n", (long unsigned)streams[1]->ssrc, streams[1]->packets_num);

		sort_stream(streams[0]);
		sort_stream(streams[1]);
		compare_streams(streams[0], streams[1]);
	}

	stream_destroy(streams[0]);
	stream_destroy(streams[1]);

	return 0;
}

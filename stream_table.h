/*
 * StreamTable.h
 *
 *  Created on: Jan 12, 2015
 *      Author: vitalik
 */

#ifndef __RTPSPY_STREAMTABLE_H__
#define __RTPSPY_STREAMTABLE_H__

/*	\brief Media stream
 */
typedef struct stream_struct         stream_t;

/*	\brief Media stream's hash table
 * */
typedef struct stream_table_struct   stream_tbl_t;

/*	\brief Stream constructor:
 *
 * @param ssrc - stream ssrc id
 * @param src  - stream source ("addr:port")
 * @param dst  - stream destination ("addr:port")
 * @param time - time elapsed from the capture start
 *
 * @result     - stream object or NULL
 */
stream_t *stream_create(uint32_t ssrc, const struct sockaddr_in *src, const struct sockaddr_in *dst, const char *dir, time_t pcap_time);

/*	\brief
 *
 * @param time   - time elapsed from the capture start
 */
ssize_t stream_add_packet(stream_t *stream, uint16_t seq, uint8_t pt, uint32_t timestamp, time_t pcap_time);


/* \brief Stream destructor
 */
void stream_destroy(stream_t *stream);


/*	\brief Media stream table constructor
 *
 * @param size       - hashe table init size
 * @stream_timeout   - media stream timeout (will be closed after)
 * @timer_interval   - stream table timer interval
 * @dump_dir         - directory for streams dumps
 */
stream_tbl_t *stream_tbl_create(size_t size, time_t stream_timeout, time_t timer_interval, char *dump_dir);

/*	\brief Media stream table destructor
 */
void stream_tbl_destroy(stream_tbl_t *tbl);

/*	\brief Adds a stream to a table
 */
ssize_t stream_tbl_add_stream(stream_tbl_t *tbl, stream_t *stream);

/*	\brief Search for a stream
 */
stream_t *stream_tbl_get_stream(stream_tbl_t *tbl, uint32_t ssrc,
                                const struct sockaddr_in *src, const struct sockaddr_in *dst,
                                time_t curr_time);

/*	\brief Stream table timer
 */
void stream_tbl_timer(stream_tbl_t *tbl, time_t current);

#endif /* __RTPSPY_STREAMTABLE_H__ */

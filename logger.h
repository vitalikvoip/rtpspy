/*
 * logger.h
 *
 *  Created on: Jan 21, 2015
 *      Author: vitalik
 */

#ifndef __RTP_SPY_LOGGER_H__
#define __RTP_SPY_LOGGER_H__

#ifdef WITH_DEBUG
#define log_debug(fmt,...) \
                printf("DEBUG -> "fmt"\n",##__VA_ARGS__)
#else
#define log_debug(fmt,...)
#endif

#ifdef WITH_DEBUG_HI
#define log_debug_hi(fmt,...) \
                printf("DEBUG -> "fmt"\n",##__VA_ARGS__)
#else
#define log_debug_hi(fmt,...)
#endif

#define log_notice(fmt,...) \
				printf("NOTICE -> "fmt"\n",##__VA_ARGS__)

#define log_error(fmt,...) \
				fprintf(stderr, "ERROR -> "fmt"\n",##__VA_ARGS__)

#endif /* __RTP_SPY_LOGGER_H__ */

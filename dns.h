#ifndef KDNS_H
#define KDNS_H

#include <linux/types.h>

#define DNS_RECORD_TTL 600
#define DNS_DB_PATH "/etc/kdns.db"
#define DNS_SERVER_PORT 8080

int kdns_init_db(void);
void kdns_destroy_db(void);

int kdns_query(u8 *req, size_t reqsize, u8 *resp);

#endif
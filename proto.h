#ifndef PROTO_H
#define PROTO_H

#include <linux/types.h>

#define DNS_HDR_SIZE sizeof(struct dns_header)

struct dns_header {
	u16 id;
	u8 qr:1;
	u8 opcode:4;
	u8 aa:1;
	u8 tc:1;
	u8 rd:1;
	u8 ra:1;
	u8 z:3;
	u8 rcode:4;
	u16 nquestions;
	u16 nanswers;
	u16 nauthorities;
	u16 nrecords;
};

struct dns_question {
	char *name;
	size_t namelen;
	int type;
	int class;
};

struct dns_answer {
	char *name;
	size_t namelen;
	int type;
	int class;
	int ttl;
	u32 addr;
};

void dns_header_parse(u8 *buf, struct dns_header *h);
void dns_header_encode(u8 *buf, struct dns_header *h);
size_t dns_question_parse(u8 *buf, struct dns_question *q);
size_t dns_answer_encode(u8 *buf, struct dns_answer *a);
int dns_is_valid_request(struct dns_header *h);
int dns_name_cmp(char *dns_name, char *name);

#endif
#include "proto.h"

#include <net/sock.h>

static void bigend_encode_u16(u8 *buf, u16 v) {
	v = htons(v);
	memcpy(buf, &v, 2);
}

static void bigend_encode_u32(u8 *buf, u32 v) {
	v = htonl(v);
	memcpy(buf, &v, 4);
}

static u16 bigend_decode_u16(u8 *buf) {
	u16 ret;
	memcpy(&ret, buf, 2);
	return ntohs(ret);
}

void dns_header_parse(u8 *buf, struct dns_header *h) {
	h->id = bigend_decode_u16(&buf[0]);
	h->qr = (buf[2] >> 7) & 0x01;
	h->opcode = (buf[2] >> 3) & 0x0F;
	h->aa = (buf[2] >> 2) & 0x01;
	h->tc = (buf[2] >> 1) & 0x01;
	h->rd = (buf[2] >> 0) & 0x01;
	h->ra = (buf[3] >> 7) & 0x01;
	h->z = (buf[3] >> 4) & 0x07;
	h->rcode = (buf[3] >> 0) & 0x0F;
	h->nquestions = bigend_decode_u16(&buf[4]);
	h->nanswers = bigend_decode_u16(&buf[6]);
	h->nauthorities = bigend_decode_u16(&buf[8]);
	h->nrecords = bigend_decode_u16(&buf[10]);
}

void dns_header_encode(u8 *buf, struct dns_header *h) {
	bigend_encode_u16(&buf[0], h->id);
	buf[2] = ((h->qr & 0x01) << 7) | ((h->opcode & 0x0F) << 3) | ((h->aa & 0x01) << 2) | ((h->tc & 0x01) << 1) | ((h->rd & 0x01) << 0);
	buf[3] = ((h->ra & 0x01) << 7) | ((h->z & 0x07) << 4) | ((h->rcode & 0x0F) << 0);
	bigend_encode_u16(&buf[4], h->nquestions);
	bigend_encode_u16(&buf[6], h->nanswers);
	bigend_encode_u16(&buf[8], h->nauthorities);
	bigend_encode_u16(&buf[10], h->nrecords);
}

size_t dns_question_parse(u8 *buf, struct dns_question *q) {
	q->name = buf;
	q->namelen = strlen(q->name);

	buf += q->namelen + 1;

	q->type = bigend_decode_u16(&buf[0]);
	q->class = bigend_decode_u16(&buf[2]);

	return q->namelen + 1 + 4;
}

size_t dns_answer_encode(u8 *buf, struct dns_answer *a) {
	memcpy(buf, a->name, a->namelen + 1);
	buf += a->namelen + 1;

	bigend_encode_u16(&buf[0], a->type);
	bigend_encode_u16(&buf[2], a->class);
	bigend_encode_u32(&buf[4], a->ttl);

	bigend_encode_u16(&buf[8], 4);
	memcpy(&buf[10], &a->addr, 4);

	return a->namelen + 1 + 10 + 4;
}

int dns_is_valid_request(struct dns_header *h) {
	return h->qr == 0 && h->opcode == 0 && h->nquestions == 1;
}

int dns_name_cmp(char *dns_name, char *name) {
	int i = 0, j = 0;
	int len;

	while (dns_name[i] != '\0' && name[j] != '\0') {
		len = dns_name[i++];
		while (len > 0 && name[j] != '\0') {
			if (dns_name[i++] != name[j++])
				return 0;
			len--;
		}
		j++;
	}

	return dns_name[i] == '\0' && name[j] == '\0';
}
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "dns.h"

#include "proto.h"

#include <linux/module.h>
#include <linux/inet.h>
#include <linux/fs.h>

#define MAX_DNS_ANSWER_CNT 4
#define FILE_BUFFER_SIZE 4096
#define MAX_DB_ENTRIES 128

struct dns_db_entry {
	char *name;
	u32 addr;
};

static int dns_db_len;
static struct dns_db_entry dns_db[MAX_DB_ENTRIES];

int kdns_init_db(void) {
	struct file *filp;
	char *rbuf;
	ssize_t rc;

	char *file_buf = kmalloc(FILE_BUFFER_SIZE, GFP_KERNEL);
	char *name_buf = kmalloc(128, GFP_KERNEL);
	char *addr_buf = kmalloc(16, GFP_KERNEL);

	filp = filp_open(DNS_DB_PATH, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		pr_err("can't open db file\n");
		return PTR_ERR(filp);
	}

	rc = kernel_read(filp, file_buf, FILE_BUFFER_SIZE - 1, 0);
	if (rc > 0) {
		int i = 0;

		file_buf[rc] = '\0';
		rbuf = file_buf;
		while (sscanf(rbuf, "%s %s", name_buf, addr_buf) == 2) {
			size_t namelen = strlen(name_buf);
			size_t addrlen = strlen(addr_buf);
			char *name = kmalloc(namelen, GFP_KERNEL);

			strcpy(name, name_buf);

			dns_db[i].name = name;
			dns_db[i].addr = in_aton(addr_buf);

			rbuf += namelen + addrlen + 2;
			i++;
		}

		dns_db_len = i;
	}

	pr_info("loaded %d dns records from the file\n", dns_db_len);

	filp_close(filp, NULL);
	kfree(addr_buf);
	kfree(name_buf);
	kfree(file_buf);
	return 0;
}

void kdns_destroy_db(void) {
	for (int i = 0; i < dns_db_len; i++) {
		kfree(dns_db[i].name);
	}
}

static int kdns_lookup(struct dns_question *quest, struct dns_answer *result) {
	int n = 0;

	if (quest->type != 1 && quest->class != 1)
		return 0;

	for (int i = 0; i < dns_db_len; i++) {
		if (dns_name_cmp(quest->name, dns_db[i].name)) {
			result[n].name = quest->name;
			result[n].namelen = quest->namelen;
			result[n].type = 1;
			result[n].class = 1;
			result[n].ttl = DNS_RECORD_TTL;
			result[n].addr = dns_db[i].addr;
			n++;
		}
	}

	return n;
}

int kdns_query(u8 *req, size_t reqsize, u8 *resp) {
	struct dns_header req_header, resp_header;
	struct dns_question quest;
	struct dns_answer answers[MAX_DNS_ANSWER_CNT];
	size_t questsize, respsize;
	int anscnt;

	dns_header_parse(req, &req_header);
	questsize = dns_question_parse(req + DNS_HDR_SIZE, &quest);

	respsize = DNS_HDR_SIZE;
	memset(&resp_header, 0, DNS_HDR_SIZE);

	resp_header.id = req_header.id;
	resp_header.qr = 1;
	resp_header.rd = req_header.rd;

	pr_info("dns request id=%d, nquestions=%d\n", req_header.id, req_header.nquestions);

	if (!dns_is_valid_request(&req_header)) {
		resp_header.rcode = 1;
		goto end;
	}

	resp_header.nquestions = 1;
	memcpy(resp + DNS_HDR_SIZE, req + DNS_HDR_SIZE, questsize);
	respsize += questsize;

	anscnt = kdns_lookup(&quest, answers);
	if (anscnt == 0) {
		resp_header.rcode = 3;
	} else {
		resp_header.nanswers = anscnt;
		for (int i = 0; i < anscnt; i++)
			respsize += dns_answer_encode(resp + respsize, &answers[i]);
	}
		pr_info("%d\n", anscnt);

end:
	dns_header_encode(resp, &resp_header);

	return respsize;
}
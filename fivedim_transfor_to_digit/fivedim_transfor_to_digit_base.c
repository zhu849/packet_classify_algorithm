#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define RULESET_SIZE 1000000
#define FILE_NAME "acl1_100k.txt"
#define OUTPUT_FILE_SIZE 10000

struct rule {
	// read from dataset
	unsigned int srcIP; // 32 bits
	unsigned int srcIP_len; // value range between 0-32
	unsigned int dstIP; // 32 bits
	unsigned int dstIP_len; // value range between 0-32
	unsigned int srcPort_upper; // 16 bits
	unsigned int srcPort_lower; // 16 bits
	unsigned int dstPort_upper; // 16 bits
	unsigned int dstPort_lower; // 16 bits	
	unsigned int protocol_1; // 8 bits
	unsigned int protocol_mask; // 8 bits
	// metadata
	unsigned int wildcard; // 1bits, if wildcard = 1 it should match. if wildcard = 0 it shouldn't match
};

/* Global variable*/
struct rule datatable[RULESET_SIZE];

void readtable() {
	char buf[200];
	char* srcIP_p, * dstIP_p, * srcPort_p, * dstPort_p, * protocol_p;
	char tok_part[] = " ";
	char tok_addr[] = "./";
	char tok_port[] = ":";
	char tok_proto[] = "x/";
	FILE* fp;
	int i;

	fp = fopen(FILE_NAME, "r");
	for (i = 0; i < OUTPUT_FILE_SIZE; i++) {
		fgets(buf, 200, fp);
		srcIP_p = strtok(buf, tok_part);
		dstIP_p = strtok(NULL, tok_part);
		srcPort_p = strtok(NULL, tok_part);
		dstPort_p = strtok(NULL, tok_part);
		protocol_p = strtok(NULL, tok_part);

		// Deal srcIP
		sprintf(buf, "%s\0", strtok(srcIP_p, tok_addr));
		datatable[i].srcIP = atoi(buf);
		datatable[i].srcIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].srcIP += atoi(buf);
		datatable[i].srcIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].srcIP += atoi(buf);
		datatable[i].srcIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].srcIP += atoi(buf);
		// Deal srcIP len
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].srcIP_len = atoi(buf);

		// Deal dstIP
		sprintf(buf, "%s\0", strtok(dstIP_p, tok_addr));
		datatable[i].dstIP = atoi(buf);
		datatable[i].dstIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].dstIP = atoi(buf);
		datatable[i].dstIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].dstIP = atoi(buf);
		datatable[i].dstIP <<= 8;
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].dstIP += atoi(buf);
		// Deal dstIP len
		sprintf(buf, "%s\0", strtok(NULL, tok_addr));
		datatable[i].dstIP_len = atoi(buf);

		// Deal srcIP port
		sprintf(buf, "%s\0", strtok(srcPort_p, tok_port));
		datatable[i].srcPort_lower = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_port));
		datatable[i].srcPort_upper = atoi(buf);

		// Deal dstIP port
		sprintf(buf, "%s\0", strtok(dstPort_p, tok_port));
		datatable[i].dstPort_lower = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_port));
		datatable[i].dstPort_upper = atoi(buf);

		// Deal protocol_1
		sprintf(buf, "%s\0", strtok(protocol_p, tok_proto));
		sprintf(buf, "%s\0", strtok(NULL, tok_proto));
		datatable[i].protocol_1 = buf[0] >= 'a' ? (buf[0] - 'a' + 10) * 16 : (buf[0] - '0') * 16;
		datatable[i].protocol_1 += buf[1] >= 'a' ? (buf[1] - 'a' + 10) : (buf[1] - '0');
		// Deal protocol_mask
		sprintf(buf, "%s\0", strtok(NULL, tok_proto));
		sprintf(buf, "%s\0", strtok(NULL, tok_proto));
		datatable[i].protocol_mask = buf[0] >= 'a' ? (buf[0] - 'a' + 10) * 16 : (buf[0] - '0') * 16;
		datatable[i].protocol_mask += buf[1] >= 'a' ? (buf[1] - 'a' + 10) : (buf[1] - '0');
	}
}

int main() {
	readtable();
	return 0;
}
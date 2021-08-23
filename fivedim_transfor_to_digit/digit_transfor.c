#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define LENS_BUF_SIZE 6
#define RULEID_LENS 17
#define INDEX_LENS 17

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
	unsigned int protocol; // 8 bits
	unsigned int protocol_mask; // 8 bits
	// metadata
	unsigned int wildcard; // 1bits, if wildcard = 1 mean protocol is *, else should check protocol field
	unsigned int ruleID; // variable
};

void file_digit_transfor(char input_path[], char output_path[]) {
	FILE* fp_r, * fp_w;
	char* p;
	char buf[200];
	int ip_buf[32], len_buf[LENS_BUF_SIZE], port_buf[16], proto_buf[8], ruleID_buf[RULEID_LENS], index_buf[INDEX_LENS];
	char tok_part[] = " :/";
	struct rule tmp;
	int i, j = 0, index = 0, index_tmp;

	//deal with subset 0 small segment
	fp_r = fopen(input_path, "r");
	fp_w = fopen(output_path, "w");
	while (fgets(buf, 200, fp_r)) {
		sprintf(buf, "%s\0", strtok(buf, tok_part));
		tmp.srcIP = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.srcIP_len = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.dstIP = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.dstIP_len = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.srcPort_lower = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.srcPort_upper = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.dstPort_lower = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.dstPort_upper = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.protocol = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.protocol_mask = atoi(buf);
		sprintf(buf, "%s\0", strtok(NULL, tok_part));
		tmp.ruleID = atoi(buf);

		// src IP
		for (i = 0; i < 32; i++) {
			ip_buf[31 - i] = tmp.srcIP % 2;
			tmp.srcIP /= 2;
		}
		for (i = 0; i < 32; i++)
			fprintf(fp_w, "%d", ip_buf[i]);
		fprintf(fp_w, "_");

		//src len
		for (i = 0; i < LENS_BUF_SIZE; i++) {
			len_buf[LENS_BUF_SIZE - 1 - i] = tmp.srcIP_len % 2;
			tmp.srcIP_len /= 2;
		}
		for (i = 0; i < LENS_BUF_SIZE; i++)
			fprintf(fp_w, "%d", len_buf[i]);
		fprintf(fp_w, "_");

		// dst IP
		for (i = 0; i < 32; i++) {
			ip_buf[31 - i] = tmp.dstIP % 2;
			tmp.dstIP /= 2;
		}
		for (i = 0; i < 32; i++)
			fprintf(fp_w, "%d", ip_buf[i]);
		fprintf(fp_w, "_");

		// dst len
		for (i = 0; i < LENS_BUF_SIZE; i++) {
			len_buf[LENS_BUF_SIZE - 1 - i] = tmp.dstIP_len % 2;
			tmp.dstIP_len /= 2;
		}
		for (i = 0; i < LENS_BUF_SIZE; i++)
			fprintf(fp_w, "%d", len_buf[i]);
		fprintf(fp_w, "_");

		// src port lower
		for (i = 0; i < 16; i++) {
			port_buf[15 - i] = tmp.srcPort_lower % 2;
			tmp.srcPort_lower /= 2;
		}
		for (i = 0; i < 16; i++)
			fprintf(fp_w, "%d", port_buf[i]);
		fprintf(fp_w, "_");

		// src port upper
		for (i = 0; i < 16; i++) {
			port_buf[15 - i] = tmp.srcPort_upper % 2;
			tmp.srcPort_upper /= 2;
		}
		for (i = 0; i < 16; i++)
			fprintf(fp_w, "%d", port_buf[i]);
		fprintf(fp_w, "_");

		// dst port lower
		for (i = 0; i < 16; i++) {
			port_buf[15 - i] = tmp.dstPort_lower % 2;
			tmp.dstPort_lower /= 2;
		}
		for (i = 0; i < 16; i++)
			fprintf(fp_w, "%d", port_buf[i]);
		fprintf(fp_w, "_");

		// src port upper
		for (i = 0; i < 16; i++) {
			port_buf[15 - i] = tmp.dstPort_upper % 2;
			tmp.dstPort_upper /= 2;
		}
		for (i = 0; i < 16; i++)
			fprintf(fp_w, "%d", port_buf[i]);
		fprintf(fp_w, "_");

		//protocol
		for (i = 0; i < 8; i++) {
			proto_buf[7 - i] = tmp.protocol % 2;
			tmp.protocol /= 2;
		}
		for (i = 0; i < 8; i++)
			fprintf(fp_w, "%d", proto_buf[i]);
		fprintf(fp_w, "_");

		// wildcard

		//rule id
		for (i = 0; i < RULEID_LENS; i++) {
			ruleID_buf[RULEID_LENS - 1 - i] = tmp.ruleID % 2;
			tmp.ruleID /= 2;
		}
		for (i = 0; i < RULEID_LENS; i++)
			fprintf(fp_w, "%d", ruleID_buf[i]);
		fprintf(fp_w, "_");

		//index
		index_tmp = index;
		printf("%d\n", index_tmp);
		for (i = 0; i < INDEX_LENS; i++) {
			index_buf[INDEX_LENS - 1 - i] = index_tmp % 2;
			index_tmp /= 2;
		}

		for (i = 0; i < INDEX_LENS; i++)
			fprintf(fp_w, "%d", index_buf[i]);
		fprintf(fp_w, "\n");

		index++;
	}

	fclose(fp_r);
	fclose(fp_w);
}

int main() {
	/*
file_digit_transfor("subset0_smallsegment.txt", "./digit/subset0_smallsegment_digit.txt");
file_digit_transfor("subset1_smallsegment.txt", "./digit/subset1_smallsegment_digit.txt");
file_digit_transfor("subset2_smallsegment.txt", "./digit/subset2_smallsegment_digit.txt");

file_digit_transfor("subset0_group0.txt", "./digit/subset0_group0_digit.txt");
file_digit_transfor("subset0_group1.txt", "./digit/subset0_group1_digit.txt");
file_digit_transfor("subset0_group2.txt", "./digit/subset0_group2_digit.txt");
file_digit_transfor("subset0_group3.txt", "./digit/subset0_group3_digit.txt");
file_digit_transfor("subset0_group4.txt", "./digit/subset0_group4_digit.txt");

file_digit_transfor("subset1_group0.txt", "./digit/subset1_group0_digit.txt");
file_digit_transfor("subset1_group1.txt", "./digit/subset1_group1_digit.txt");
file_digit_transfor("subset1_group2.txt", "./digit/subset1_group2_digit.txt");
file_digit_transfor("subset1_group3.txt", "./digit/subset1_group3_digit.txt");
file_digit_transfor("subset1_group4.txt", "./digit/subset1_group4_digit.txt");

file_digit_transfor("subset2_group0.txt", "./digit/subset2_group0_digit.txt");
file_digit_transfor("subset2_group1.txt", "./digit/subset2_group1_digit.txt");
file_digit_transfor("subset2_group2.txt", "./digit/subset2_group2_digit.txt");
file_digit_transfor("subset2_group3.txt", "./digit/subset2_group3_digit.txt");
file_digit_transfor("subset2_group4.txt", "./digit/subset2_group4_digit.txt");
*/
	return 0;
}
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>

#define FILE_NAME "acl1_100k_yu.txt"
#define RULESET_SIZE 99833
#define MAGIC_NUM 0x80008001
#define T1 10
#define BIGSEGMENT_SIZE 500
#define SMALLSEGMENT_SIZE 10000

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
	unsigned int wildcard; // 1bits, if wildcard = 1 it should check matched. if wildcard = 0 it shouldn't check matched
};

/* Global variable*/
struct rule datatable[RULESET_SIZE];
struct rule subset[4][RULESET_SIZE];
int k[3];
int segment_table_count[4][65536] = {0};
int *big_segment;

int subset_rulenum[4] = { 0,0,0,0 };
int subset_count[4] = { 0,0,0,0 };

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
	for (i = 0; i < RULESET_SIZE; i++) {
		if (fgets(buf, 200, fp)) {
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
}

void classify_subset() {
	int i;
	int log2;

	// count # of rule in subset
	for (i = 0; i < RULESET_SIZE; i++) {
		if (datatable[i].srcIP_len > 15 && datatable[i].dstIP_len > 15)
			subset_rulenum[0]++;
		else if (datatable[i].srcIP_len > 15 && datatable[i].dstIP_len <= 15)
			subset_rulenum[1]++;
		else if (datatable[i].srcIP_len <= 15 && datatable[i].dstIP_len > 15)
			subset_rulenum[2]++;
		else if(datatable[i].srcIP_len <= 15 && datatable[i].dstIP_len <= 15)
			subset_rulenum[3]++;
	}

	for (i = 0; i < 3; i++) {
		log2 = 0;
		while (pow(2, log2) < subset_rulenum[i])
			log2++;
		k[i] = log2;
	}
	
	for (i = 0; i < RULESET_SIZE; i++) {
		if (datatable[i].srcIP_len >= k[0] && datatable[i].dstIP_len >= k[0]) 
			subset[0][subset_count[0]++] = datatable[i];
		else if(datatable[i].srcIP_len >= k[1])
			subset[1][subset_count[1]++] = datatable[i];
		else if(datatable[i].dstIP_len >= k[2])
			subset[2][subset_count[2]++] = datatable[i];
		else
			subset[3][subset_count[3]++] = datatable[i];
	}
}

void classify_segment() {
	FILE *fp_s0_big, *fp_s0_small, *fp_s1_big, *fp_s1_small, *fp_s2_big, *fp_s2_small, *fp_s3;
	char buf[200];
	int i, j;
	int hashkey;

	fp_s0_big = fopen("subset0_bigsegment.txt", "w");
	fp_s0_small = fopen("subset0_smallsegment.txt", "w");
	fp_s1_big = fopen("subset1_bigsegment.txt", "w");
	fp_s1_small = fopen("subset1_smallsegment.txt", "w");
	fp_s2_big = fopen("subset2_bigsegment.txt", "w");
	fp_s2_small = fopen("subset2_smallsegment.txt", "w");
	fp_s3 = fopen("subset3_segment.txt", "w");

	for (i = 0; i < 4; i++) {
		if (i == 0) {
			// count segment table size
			for (j = 0; j < subset_count[0]; j++) {
				hashkey = subset[0][j].srcIP >> (32 - k[0]);
				hashkey << k[0];
				hashkey += subset[0][j].dstIP >> (32 - k[0]);
				hashkey = (hashkey * MAGIC_NUM) >> (32 - k[0]);
				segment_table_count[0][hashkey]++;
			}

			// Output file
			for (j = 0; j < subset_count[0]; j++) {
				hashkey = subset[0][j].srcIP >> (32 - k[0]);
				hashkey << k[0];
				hashkey += subset[0][j].dstIP >> (32 - k[0]);
				hashkey = (hashkey * MAGIC_NUM) >> (32 - k[0]);
				// big segment
				if (segment_table_count[0][hashkey] >= T1) {
					fprintf(fp_s0_big, "%u %u %u:%u %u:%u %u/%u\n", subset[0][j].srcIP, subset[0][j].dstIP, subset[0][j].srcPort_lower, subset[0][j].srcPort_upper, subset[0][j].dstPort_lower, subset[0][j].dstPort_upper, subset[0][j].protocol_1, subset[0][j].protocol_mask);
				}
				// small segment
				else {
					fprintf(fp_s0_small, "%u %u %u:%u %u:%u %u/%u\n", subset[0][j].srcIP, subset[0][j].dstIP, subset[0][j].srcPort_lower, subset[0][j].srcPort_upper, subset[0][j].dstPort_lower, subset[0][j].dstPort_upper, subset[0][j].protocol_1, subset[0][j].protocol_mask);
				}
			}
		}
		else if (i == 1) {
			// Count segment table size
			for (j = 0; j < subset_count[1]; j++) {
				hashkey = subset[1][j].srcIP >> (32 - k[1]);
				segment_table_count[1][hashkey]++;
			}
			// Output file
			for (j = 0; j < subset_count[1]; j++) {
				hashkey = subset[1][j].srcIP >> (32 - k[1]);
				// big segment
				if (segment_table_count[1][hashkey] >= T1) {
					fprintf(fp_s1_big, "%u %u %u:%u %u:%u %u/%u\n", subset[1][j].srcIP, subset[1][j].dstIP, subset[1][j].srcPort_lower, subset[1][j].srcPort_upper, subset[1][j].dstPort_lower, subset[1][j].dstPort_upper, subset[1][j].protocol_1, subset[1][j].protocol_mask);
				}
				// small segment
				else {
					fprintf(fp_s1_small, "%u %u %u:%u %u:%u %u/%u\n", subset[1][j].srcIP, subset[1][j].dstIP, subset[1][j].srcPort_lower, subset[1][j].srcPort_upper, subset[1][j].dstPort_lower, subset[1][j].dstPort_upper, subset[1][j].protocol_1, subset[1][j].protocol_mask);
				}
			}
		}
		else if (i == 2) {
			// Count segment table size
			for (j = 0; j < subset_count[2]; j++) {
				hashkey = subset[2][j].dstIP >> (32 - k[2]);
				segment_table_count[2][hashkey]++;
			}
			// Output file
			for (j = 0; j < subset_count[2]; j++) {
				hashkey = subset[2][j].dstIP >> (32 - k[2]);
				// big segment
				if (segment_table_count[2][hashkey] >= T1) {
					fprintf(fp_s2_big, "%u %u %u:%u %u:%u %u/%u\n", subset[2][j].srcIP, subset[2][j].dstIP, subset[2][j].srcPort_lower, subset[2][j].srcPort_upper, subset[2][j].dstPort_lower, subset[2][j].dstPort_upper, subset[2][j].protocol_1, subset[2][j].protocol_mask);
				}
				// small segment
				else {
					fprintf(fp_s2_small, "%u %u %u:%u %u:%u %u/%u\n", subset[2][j].srcIP, subset[2][j].dstIP, subset[2][j].srcPort_lower, subset[2][j].srcPort_upper, subset[2][j].dstPort_lower, subset[2][j].dstPort_upper, subset[2][j].protocol_1, subset[2][j].protocol_mask);
				}
			}
		}
		else {
			for (j = 0; j < subset_count[3]; j++) {
				fprintf(fp_s3, "%u %u %u:%u %u:%u %u/%u\n", subset[3][j].srcIP, subset[3][j].dstIP, subset[3][j].srcPort_lower, subset[3][j].srcPort_upper, subset[3][j].dstPort_upper, subset[3][j].dstPort_lower, subset[3][j].protocol_1, subset[3][j].protocol_mask);
				segment_table_count[3][0]++;
			}
		}
	}

	fclose(fp_s0_big);
	fclose(fp_s0_small);
	fclose(fp_s1_big);
	fclose(fp_s1_small);
	fclose(fp_s2_big);
	fclose(fp_s2_small);
	fclose(fp_s3);
}

int main() {
	readtable();
	classify_subset();
	classify_segment();

	int i, j;
	
	printf("---------------------------# of rules in original subset---------------------------\n");
	for (i = 0; i < 4; i++) {
		printf("original # of rule in subset[%d]:%d\n", i, subset_rulenum[i]);
	}
	printf("---------------------------# of rules in subset---------------------------\n");
	for (i = 0; i < 4; i++) {
		printf("# of rule in subset[%d]:%d\n", i, subset_count[i]);
	}
	printf("--------------------------- k ---------------------------\n");
	for (i = 0; i < 3; i++)
		printf("k[%d]:%d\n", i,k[i]);
	/*
	printf("--------------------------- # of rule in segment table & subset ---------------------------\n");
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 65536; i++) {
			if (segment_table_count[j][i] != 0)
				printf("segment_table_count[%d][%d]:%d\n", j, i, segment_table_count[j][i]);
		}
	}
	*/



	return 0;
}
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>

#define FILE_NAME "./dataset/ipc2_100k"
#define RULESET_SIZE 100000
#define T1 10
#define T2 4
#define NUM_OF_BIGSENGMENT 500 // pre-allocated size
#define BIGSEGMENT_MAX_SIZE 100 // pre-allocated size

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
	unsigned int index; 
};

/* Global variable*/
struct rule datatable[RULESET_SIZE];// use by readtable()

struct rule subset[4][RULESET_SIZE];// subset table after cut
int k[3];
int subset_rulenum[4] = { 0,0,0,0 }; // record # of rule with original cut method(16,16)
int subset_count[4] = { 0,0,0,0 }; //record # of rule with new cut method

struct rule bigsegment[3][65536][BIGSEGMENT_MAX_SIZE];
int segment_table_count[4][65536] = { 0 };// how many rule in segment table with this subset
int bigsegment_size[3][65536] = { 0 }; // cell size of all bigsegment in this subset, total size should sum it all 65536 segment element size
int group_count[4][65536][5] = { 0 };// count group size

void readtable() {
	char buf[200];
	char* srcIP_p, * dstIP_p, * srcPort_p, * dstPort_p, * protocol_p;
	char tok_part[] = "@ ";
	char tok_addr[] = "./";
	char tok_port[] = ":";
	char tok_proto[] = "x/";
	FILE* fp;
	int i, id = 0;

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

			// Deal protocol
			sprintf(buf, "%s\0", strtok(protocol_p, tok_proto));
			sprintf(buf, "%s\0", strtok(NULL, tok_proto));
			datatable[i].protocol = buf[0] >= 'a' ? (buf[0] - 'a' + 10) * 16 : (buf[0] - '0') * 16;
			datatable[i].protocol += buf[1] >= 'a' ? (buf[1] - 'a' + 10) : (buf[1] - '0');
			
			// Deal protocol_mask
			sprintf(buf, "%s\0", strtok(NULL, tok_proto));
			sprintf(buf, "%s\0", strtok(NULL, tok_proto));
			datatable[i].protocol_mask = buf[0] >= 'a' ? (buf[0] - 'a' + 10) * 16 : (buf[0] - '0') * 16;
			datatable[i].protocol_mask += buf[1] >= 'a' ? (buf[1] - 'a' + 10) : (buf[1] - '0');
			
			// Deal id
			datatable[i].ruleID = id;
			id++;
		}
	}
}

int subset0_hash(unsigned int num, int len) {
	switch (len) {
	case 4:
		num = (num * 0x88888889) >> (32-len);
		break;
	case 5:
	case 6:
	case 7:
	case 8:
		num = (num * 0x80808081) >> (32 - len);
		break;
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		num = (num * 0x80008001) >> (32 - len);
		break;
	default:
		printf("hash error \n");
		num = 0;
	}
	return num;
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
		//log2 = 0;
		//while (pow(2, log2) < subset_rulenum[i])
		//	log2++;
		//k[i] = log2;
		k[i] = 16;
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
	FILE *fp_s0_small, *fp_s1_small, *fp_s2_small, *fp_s3;
	int i, j;
	int hashkey;

	fp_s0_small = fopen("subset0_smallsegment.txt", "w");
	fp_s1_small = fopen("subset1_smallsegment.txt", "w");
	fp_s2_small = fopen("subset2_smallsegment.txt", "w");
	fp_s3 = fopen("subset3_segment.txt", "w");

	// deal subset 0-3
	for (i = 0; i < 4; i++) {
		if (i == 0) {
			// count the cell's size in segment table，算 segment table 內每一格有多少 rule
			for (j = 0; j < subset_count[0]; j++) {
				hashkey = subset[0][j].srcIP >> (32 - k[0]);
				hashkey << k[0];
				hashkey += subset[0][j].dstIP >> (32 - k[0]);
				hashkey = subset0_hash(hashkey, k[0]);
				segment_table_count[0][hashkey]++;
			}

			// Output file
			for (j = 0; j < subset_count[0]; j++) {
				hashkey = subset[0][j].srcIP >> (32 - k[0]);
				hashkey << k[0];
				hashkey += subset[0][j].dstIP >> (32 - k[0]);
				hashkey = subset0_hash(hashkey, k[0]);

				// big segment, should output hashkey here
				if (segment_table_count[0][hashkey] >= T1) 
					bigsegment[0][hashkey][bigsegment_size[0][hashkey]++] = subset[0][j];
				// small segment
				else 
					fprintf(fp_s0_small, "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[0][j].srcIP,  subset[0][j].srcIP_len,  subset[0][j].dstIP, subset[0][j].dstIP_len, subset[0][j].srcPort_lower, subset[0][j].srcPort_upper, subset[0][j].dstPort_lower, subset[0][j].dstPort_upper, subset[0][j].protocol, subset[0][j].protocol_mask, subset[0][j].ruleID);
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
				if (segment_table_count[1][hashkey] >= T1)
					bigsegment[1][hashkey][bigsegment_size[1][hashkey]++] = subset[1][j];
				// small segment
				else 
					fprintf(fp_s1_small, "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[1][j].srcIP, subset[1][j].srcIP_len, subset[1][j].dstIP, subset[1][j].dstIP_len, subset[1][j].srcPort_lower, subset[1][j].srcPort_upper, subset[1][j].dstPort_lower, subset[1][j].dstPort_upper, subset[1][j].protocol, subset[1][j].protocol_mask, subset[1][j].ruleID);
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
				if (segment_table_count[2][hashkey] >= T1) 
					bigsegment[2][hashkey][bigsegment_size[2][hashkey]++] = subset[2][j];
				// small segment
				else 
					fprintf(fp_s2_small, "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[2][j].srcIP, subset[2][j].srcIP_len, subset[2][j].dstIP, subset[2][j].dstIP_len, subset[2][j].srcPort_lower, subset[2][j].srcPort_upper, subset[2][j].dstPort_lower, subset[2][j].dstPort_upper, subset[2][j].protocol, subset[2][j].protocol_mask, subset[2][j].ruleID);
			}
		}
		else {
			for (j = 0; j < subset_count[3]; j++) {
				fprintf(fp_s3, "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][j].srcIP, subset[3][j].srcIP_len, subset[3][j].dstIP, subset[3][j].dstIP_len, subset[3][j].srcPort_lower, subset[3][j].srcPort_upper, subset[3][j].dstPort_lower, subset[3][j].dstPort_upper, subset[3][j].protocol, subset[3][j].protocol_mask, subset[3][j].ruleID);
				segment_table_count[3][0]++;
			}
		}
	}

	fclose(fp_s0_small);
	fclose(fp_s1_small);
	fclose(fp_s2_small);
	fclose(fp_s3);
}

void classify_group() {
	int i, j, t;

	FILE *fp_s0_gp_small[5], *fp_s1_gp_small[5], *fp_s2_gp_small[5],*fp_s3_gp_small[5], *fp_s0_gp_big[5], *fp_s1_gp_big[5], *fp_s2_gp_big[5],*fp_s3_gp_big[5];
	
	fp_s0_gp_small[0] = fopen("subset0_group0_small.txt", "w");
	fp_s0_gp_small[1] = fopen("subset0_group1_small.txt", "w");
	fp_s0_gp_small[2] = fopen("subset0_group2_small.txt", "w");
	fp_s0_gp_small[3] = fopen("subset0_group3_small.txt", "w");
	fp_s0_gp_small[4] = fopen("subset0_group4_small.txt", "w");
	fp_s1_gp_small[0] = fopen("subset1_group0_small.txt", "w");
	fp_s1_gp_small[1] = fopen("subset1_group1_small.txt", "w");
	fp_s1_gp_small[2] = fopen("subset1_group2_small.txt", "w");
	fp_s1_gp_small[3] = fopen("subset1_group3_small.txt", "w");
	fp_s1_gp_small[4] = fopen("subset1_group4_small.txt", "w");
	fp_s2_gp_small[0] = fopen("subset2_group0_small.txt", "w");
	fp_s2_gp_small[1] = fopen("subset2_group1_small.txt", "w");
	fp_s2_gp_small[2] = fopen("subset2_group2_small.txt", "w");
	fp_s2_gp_small[3] = fopen("subset2_group3_small.txt", "w");
	fp_s2_gp_small[4] = fopen("subset2_group4_small.txt", "w");
	fp_s3_gp_small[0] = fopen("subset3_group0_small.txt", "w");
	fp_s3_gp_small[1] = fopen("subset3_group1_small.txt", "w");
	fp_s3_gp_small[2] = fopen("subset3_group2_small.txt", "w");
	fp_s3_gp_small[3] = fopen("subset3_group3_small.txt", "w");
	fp_s3_gp_small[4] = fopen("subset3_group4_small.txt", "w");

	fp_s0_gp_big[0] = fopen("subset0_group0_big.txt", "w");
	fp_s0_gp_big[1] = fopen("subset0_group1_big.txt", "w");
	fp_s0_gp_big[2] = fopen("subset0_group2_big.txt", "w");
	fp_s0_gp_big[3] = fopen("subset0_group3_big.txt", "w");
	fp_s0_gp_big[4] = fopen("subset0_group4_big.txt", "w");
	fp_s1_gp_big[0] = fopen("subset1_group0_big.txt", "w");
	fp_s1_gp_big[1] = fopen("subset1_group1_big.txt", "w");
	fp_s1_gp_big[2] = fopen("subset1_group2_big.txt", "w");
	fp_s1_gp_big[3] = fopen("subset1_group3_big.txt", "w");
	fp_s1_gp_big[4] = fopen("subset1_group4_big.txt", "w");
	fp_s2_gp_big[0] = fopen("subset2_group0_big.txt", "w");
	fp_s2_gp_big[1] = fopen("subset2_group1_big.txt", "w");
	fp_s2_gp_big[2] = fopen("subset2_group2_big.txt", "w");
	fp_s2_gp_big[3] = fopen("subset2_group3_big.txt", "w");
	fp_s2_gp_big[4] = fopen("subset2_group4_big.txt", "w");
	fp_s3_gp_big[0] = fopen("subset3_group0_big.txt", "w");
	fp_s3_gp_big[1] = fopen("subset3_group1_big.txt", "w");
	fp_s3_gp_big[2] = fopen("subset3_group2_big.txt", "w");
	fp_s3_gp_big[3] = fopen("subset3_group3_big.txt", "w");
	fp_s3_gp_big[4] = fopen("subset3_group4_big.txt", "w");
	

	for (i = 0; i < 3; i++) {
		if (i == 0) {
			// count group size
			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[0][j]; t++) {
					// G0
					if (bigsegment[0][j][t].srcIP >= 30)
						group_count[0][j][0]++;
					// G1
					else if (bigsegment[0][j][t].dstIP >= 30) 
						group_count[0][j][1]++;
					// G2
					else if (bigsegment[0][j][t].dstPort_upper - bigsegment[0][j][t].dstPort_lower == 0)
						group_count[0][j][2]++;
					// G3
					else if (bigsegment[0][j][t].srcPort_upper - bigsegment[0][j][t].srcPort_lower == 0) 
						group_count[0][j][3]++;
					// G4
					else 
						group_count[0][j][4]++;
				}
			}

			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[0][j]; t++) {
					// G0
					if (bigsegment[0][j][t].srcIP >= 30) {
						// big group
						if (group_count[0][j][0] > T2)
							fprintf(fp_s0_gp_big[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
						// small group
						else 
							fprintf(fp_s0_gp_small[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
					}
					// G1
					else if (bigsegment[0][j][t].dstIP >= 30) {
						// big group
						if (group_count[0][j][1] > T2)
							fprintf(fp_s0_gp_big[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
						// small group
						else
							fprintf(fp_s0_gp_small[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
					}
					// G2
					else if (bigsegment[0][j][t].dstPort_upper - bigsegment[0][j][t].dstPort_lower == 0) {
						// big group
						if (group_count[0][j][2] > T2)
							fprintf(fp_s0_gp_big[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
						// small group
						else
							fprintf(fp_s0_gp_small[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
					}
					// G3
					else if (bigsegment[0][j][t].srcPort_upper - bigsegment[0][j][t].srcPort_lower == 0) {
						// big group
						if (group_count[0][j][3] > T2)
							fprintf(fp_s0_gp_big[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
						// small group
						else
							fprintf(fp_s0_gp_small[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
					}
					// G4
					else {
						// big group
						if (group_count[0][j][4] > T2)
							fprintf(fp_s0_gp_big[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
						// small group
						else
							fprintf(fp_s0_gp_small[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[0][j][t].srcIP, bigsegment[0][j][t].srcIP_len, bigsegment[0][j][t].dstIP, bigsegment[0][j][t].dstIP_len, bigsegment[0][j][t].srcPort_lower, bigsegment[0][j][t].srcPort_upper, bigsegment[0][j][t].dstPort_lower, bigsegment[0][j][t].dstPort_upper, bigsegment[0][j][t].protocol, bigsegment[0][j][t].protocol_mask, bigsegment[0][j][t].ruleID);
					}
				}
			}
		}
		else if (i == 1) {
			// count group size
			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[1][j]; t++) {
					// G0
					if (bigsegment[1][j][t].srcIP >= 30)
						group_count[1][j][0]++;
					// G1
					else if (bigsegment[1][j][t].dstIP >= 30)
						group_count[1][j][1]++;
					// G2
					else if (bigsegment[1][j][t].dstPort_upper - bigsegment[1][j][t].dstPort_lower == 0)
						group_count[1][j][2]++;
					// G3
					else if (bigsegment[1][j][t].srcPort_upper - bigsegment[1][j][t].srcPort_lower == 0)
						group_count[1][j][3]++;
					// G4
					else
						group_count[1][j][4]++;
				}
			}

			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[1][j]; t++) {
					// G0
					if (bigsegment[1][j][t].srcIP >= 30) {
						// big group
						if (group_count[1][j][0] > T2)
							fprintf(fp_s1_gp_big[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
						// small group
						else
							fprintf(fp_s1_gp_small[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
					}
					// G1
					else if (bigsegment[1][j][t].dstIP >= 30) {
						// big group
						if (group_count[1][j][1] > T2)
							fprintf(fp_s1_gp_big[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
						// small group
						else
							fprintf(fp_s1_gp_small[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
					}
					// G2
					else if (bigsegment[1][j][t].dstPort_upper - bigsegment[1][j][t].dstPort_lower == 0) {
						// big group
						if (group_count[1][j][2] > T2)
							fprintf(fp_s1_gp_big[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
						// small group
						else
							fprintf(fp_s1_gp_small[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
					}
					// G3
					else if (bigsegment[1][j][t].srcPort_upper - bigsegment[1][j][t].srcPort_lower == 0) {
						// big group
						if (group_count[1][j][3] > T2)
							fprintf(fp_s1_gp_big[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
						// small group
						else
							fprintf(fp_s1_gp_small[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
					}
					// G4
					else {
						// big group
						if (group_count[1][j][4] > T2)
							fprintf(fp_s1_gp_big[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
						// small group
						else
							fprintf(fp_s1_gp_small[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[1][j][t].srcIP, bigsegment[1][j][t].srcIP_len, bigsegment[1][j][t].dstIP, bigsegment[1][j][t].dstIP_len, bigsegment[1][j][t].srcPort_lower, bigsegment[1][j][t].srcPort_upper, bigsegment[1][j][t].dstPort_lower, bigsegment[1][j][t].dstPort_upper, bigsegment[1][j][t].protocol, bigsegment[1][j][t].protocol_mask, bigsegment[1][j][t].ruleID);
					}
				}
			}
		}
		else if(i==2){
			// count group size
			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[2][j]; t++) {
					// G0
					if (bigsegment[2][j][t].srcIP >= 30)
						group_count[2][j][0]++;
					// G1
					else if (bigsegment[2][j][t].dstIP >= 30)
						group_count[2][j][1]++;
					// G2
					else if (bigsegment[2][j][t].dstPort_upper - bigsegment[2][j][t].dstPort_lower == 0)
						group_count[2][j][2]++;
					// G3
					else if (bigsegment[2][j][t].srcPort_upper - bigsegment[2][j][t].srcPort_lower == 0)
						group_count[2][j][3]++;
					// G4
					else
						group_count[2][j][4]++;
				}
			}

			for (j = 0; j < 65536; j++) {
				for (t = 0; t < bigsegment_size[2][j]; t++) {
					// G0
					if (bigsegment[2][j][t].srcIP >= 30) {
						// big group
						if (group_count[2][j][0] > T2)
							fprintf(fp_s2_gp_big[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
						// small group
						else
							fprintf(fp_s2_gp_small[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
					}
					// G1
					else if (bigsegment[2][j][t].dstIP >= 30) {
						// big group
						if (group_count[2][j][1] > T2)
							fprintf(fp_s2_gp_big[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
						// small group
						else
							fprintf(fp_s2_gp_small[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
					}
					// G2
					else if (bigsegment[2][j][t].dstPort_upper - bigsegment[2][j][t].dstPort_lower == 0) {
						// big group
						if (group_count[2][j][2] > T2)
							fprintf(fp_s2_gp_big[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
						// small group
						else
							fprintf(fp_s2_gp_small[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
					}
					// G3
					else if (bigsegment[2][j][t].srcPort_upper - bigsegment[2][j][t].srcPort_lower == 0) {
						// big group
						if (group_count[2][j][3] > T2)
							fprintf(fp_s2_gp_big[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
						// small group
						else
							fprintf(fp_s2_gp_small[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
					}
					// G4
					else {
						// big group
						if (group_count[2][j][4] > T2)
							fprintf(fp_s2_gp_big[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
						// small group
						else
							fprintf(fp_s2_gp_small[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", bigsegment[2][j][t].srcIP, bigsegment[2][j][t].srcIP_len, bigsegment[2][j][t].dstIP, bigsegment[2][j][t].dstIP_len, bigsegment[2][j][t].srcPort_lower, bigsegment[2][j][t].srcPort_upper, bigsegment[2][j][t].dstPort_lower, bigsegment[2][j][t].dstPort_upper, bigsegment[2][j][t].protocol, bigsegment[2][j][t].protocol_mask, bigsegment[2][j][t].ruleID);
					}
				}
			}
		}
	}

	// deal subset 3
	for (i = 0; i < subset_count[3]; i++) {
		// G0
		if (subset[3][i].srcIP >= 30)
			group_count[3][0][0]++;
		// G1
		else if (subset[3][i].dstIP >= 30)
			group_count[3][0][1]++;
		// G2
		else if (subset[3][i].dstPort_upper - subset[3][i].dstPort_lower == 0)
			group_count[3][0][2]++;
		// G3
		else if (subset[3][i].srcPort_upper - subset[3][i].srcPort_lower == 0)
			group_count[3][0][3]++;
		// G4
		else
			group_count[3][0][4]++;
	}

	for (i = 0; i < subset_count[3]; i++) {
		// G0
		if (subset[3][i].srcIP >= 30) {
			// big group
			if (group_count[3][0][0] > T2)
				fprintf(fp_s3_gp_big[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
			// small group
			else
				fprintf(fp_s3_gp_small[0], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
		}
		// G1
		else if (subset[3][i].dstIP >= 30) {
			// big group
			if (group_count[3][0][1] > T2)
				fprintf(fp_s3_gp_big[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
			// small group
			else
				fprintf(fp_s3_gp_small[1], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
		}
		// G2
		else if (subset[3][i].dstPort_upper - subset[3][i].dstPort_lower == 0) {
			// big group
			if (group_count[3][0][2] > T2)
				fprintf(fp_s3_gp_big[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
			// small group
			else
				fprintf(fp_s3_gp_small[2], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
		}
		// G3
		else if (subset[3][i].srcPort_upper - subset[3][i].srcPort_lower == 0) {
			// big group
			if (group_count[3][0][3] > T2)
				fprintf(fp_s3_gp_big[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
			// small group
			else
				fprintf(fp_s3_gp_small[3], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
		}
		// G4
		else {
			// big group
			if (group_count[3][0][4] > T2)
				fprintf(fp_s3_gp_big[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
			// small group
			else
				fprintf(fp_s3_gp_small[4], "%u %u %u %u %u:%u %u:%u %u/%u %u\n", subset[3][i].srcIP, subset[3][i].srcIP_len, subset[3][i].dstIP, subset[3][i].dstIP_len, subset[3][i].srcPort_lower, subset[3][i].srcPort_upper, subset[3][i].dstPort_lower, subset[3][i].dstPort_upper, subset[3][i].protocol, subset[3][i].protocol_mask, subset[3][i].ruleID);
		}
	}

	for (i = 0; i < 5; i++) {
		fclose(fp_s0_gp_small[i]);
		fclose(fp_s1_gp_small[i]);
		fclose(fp_s2_gp_small[i]);
		fclose(fp_s3_gp_small[i]);
		fclose(fp_s0_gp_big[i]);
		fclose(fp_s1_gp_big[i]);
		fclose(fp_s2_gp_big[i]);
		fclose(fp_s3_gp_big[i]);
	}
}


int main() {
	int i, j, t;
	readtable();

	classify_subset();
	printf("---------------------------# of rules in original subset(cut with tuple (16, 16))---------------------------\n");
	for (i = 0; i < 4; i++)
		printf("original # of rule in subset[%d]:%d\n", i, subset_rulenum[i]);
	printf("--------------------------- cut len \"k\" ---------------------------\n");
	for (i = 0; i < 3; i++)
		printf("k[%d]:%d\n", i,k[i]);
	printf("---------------------------# of rules in subset after recut---------------------------\n");
	for (i = 0; i < 4; i++)
		printf("# of rule in subset[%d]:%d\n", i, subset_count[i]);

	classify_segment();
	printf("--------------------------- # of rule in segment table with every subset ---------------------------\n");
	for (j = 0; j < 4; j++) {
		int segment_zero = 0;
		int segment_small = 0;
		int segment_big = 0;
		for (i = 0; i < 65536; i++) {
			if (segment_table_count[j][i] == 0) 
				segment_zero++;
			else if (segment_table_count[j][i] < T1) 
				segment_small++;
			else 
				segment_big++;
		}
		printf("subset %d size segment cell -> ==0:%d, <10:%d, >=10:%d \n", j,  segment_zero, segment_small, segment_big);
	}
	classify_group();

	printf("--------------------------- # of rule in segment table with every subset in every group ---------------------------\n");
	for (i = 0; i < 4; i++) {
		int group_zero = 0;
		int group_small = 0;
		int group_big = 0;
		int group_total[5] = { 0 };
		for (t = 0; t < 65536; t++) {
			for (j = 0; j < 5; j++) {
				group_total[j] += group_count[i][t][j];
				if (group_count[i][t][j] == 0)
					group_zero++;
				else if (group_count[i][t][j] < T2)
					group_small++;
				else
					group_big++;
			}
		}
		printf("subset %d - zero group:%d, small group:%d, big group:%d\n", i, group_zero, group_small, group_big);
		printf("subset %d G0:%d, G1:%d, G2:%d, G3:%d, G4:%d\n", i, group_total[0], group_total[1], group_total[2], group_total[3], group_total[4]);
	}

	

	return 0;
}
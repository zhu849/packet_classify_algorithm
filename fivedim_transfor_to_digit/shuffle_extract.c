#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define INPUT_FILE_NAME "./100k/acl1_100k"
#define OUTPUT_FILE_NAME "./10k/acl1_10k"
#define INPUT_SIZE 99833
#define OUTPUT_SIZE 10000

char datatable[INPUT_SIZE][200];

void readtable() {
	char buf[200];
	FILE* fp;
	fp = fopen(INPUT_FILE_NAME, "r");

	for (int i = 0; i < INPUT_SIZE; i++)
		fgets(datatable[i], 200, fp);
	fclose(fp);
}

void shuffle() {
	srand((unsigned)time(NULL));
	char temp[200] = "";
	for (int i = 0; i < INPUT_SIZE; i++) {
		size_t j = i + rand() / (RAND_MAX / (INPUT_SIZE - i) + 1);
		strcpy(temp, datatable[j]);
		strcpy(datatable[j], datatable[i]);
		strcpy(datatable[i], temp);
	}
}

void extract() {
	FILE* fp;
	fp = fopen(OUTPUT_FILE_NAME, "w");
	int j;

	for (int i = 0; i < OUTPUT_SIZE; i++) {
		j = 0;
		while (datatable[i][j] != '\n')
			fprintf(fp, "%c", datatable[i][j++]);
		fprintf(fp, "\n");
	}
	fclose(fp);
}

int main() {
	readtable();
	shuffle();
	extract();
}


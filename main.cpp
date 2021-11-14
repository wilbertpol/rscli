/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#include <getopt.h>
#include "psarc.h"

#define VERSION "0.2 alpha"

void usage() {
	printf("Usage: rscli [options/commands]\n");
	printf("Options/commands:\n");
	printf("\t-i:--input\tInput psarc file to use\n");
	printf("\t-l:--list\tList id, size, and name of every file in the archive\n");
	printf("\t-e:--extract\tExtract all files\n");
//	printf("\t-v\t\tDisplay version.\n");
}

static int verbose_flag;

int main(int argc, char *argv[]) {
	PSARC psarc;
	char *inputFileName = NULL;
	bool doList = false;
	bool doExport = false;

	static struct option long_options[] = {
		/* These options set a flag. */
	  {"brief",   no_argument,       &verbose_flag, 0},
	  /* These options don’t set a flag. We distinguish them by their indices. */
	  {"list",    no_argument,       0, 'l'},
	  {"extract", no_argument,       0, 'e'},
	  {"input",   required_argument, 0, 'i'},
	  {0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "i:le", long_options, &option_index);
		if (c == -1) break;
		switch (c)
			{
			case 'l':
			  doList = true;
				break;

			case 'e':
				doExport = true;
				break;

			case 'i':
				inputFileName = optarg;
				break;

			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort();
			}
	}

	if (inputFileName == NULL) {
		printf("No inputfile specified\n");
		usage();
		exit(1);
	}

	if (!psarc.read(inputFileName)) {
		printf("Unable to open archive '%s'\n", inputFileName);
		exit(1);
	}
	if (doList) {
		psarc.displayFileList();
	}
	if (doExport) {
		psarc.extractAllFiles();
	}

	return EXIT_SUCCESS;
}

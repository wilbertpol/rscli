/*
 * Based on
 * Open PSARC PS3 extractor v0.1.18
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#include <getopt.h>
#include "psarc.h"
#include "options.h"


#define VERSION "0.2 alpha"


void usage() {
	printf("Usage: rscli [options/commands]\n");
	printf("Options/commands:\n");
	printf("\t-i:--input [filename]\tInput psarc file to use.\n");
	printf("\t-l:--list\t\tList id, size, and name of every file in the archive.\n");
	printf("\t-e:--extract\t\tExtract all files.\n");
	printf("\t\t\t\tEncrypted .sng files will be decrypted during extraction.\n");
	printf("\t-o:--output [filename]\tOutput psarc file to write to (overwrites the file). (TODO)\n");
	printf("\t-a:--appid [appid]\tSet AppID to the supplied value. (TODO)\n");
	printf("\t-p:--platform [pc|mac]\tWrite .sng files as pc/mac in the output psarc file. (TODO)\n");
//	printf("\t-v\t\tDisplay version.\n");
}

int main(int argc, char *argv[]) {
	PSARC psarc;
	Options options;
	int verbose_flag;

	static struct option long_options[] = {
		/* These options set a flag. */
	  {"brief",    no_argument,       &verbose_flag, 0},
	  /* These options don’t set a flag. We distinguish them by their indices. */
	  {"list",     no_argument,       0, 'l'},
	  {"extract",  no_argument,       0, 'e'},
	  {"input",    required_argument, 0, 'i'},
		{"output",   required_argument, 0, 'o'},
		{"appid",    required_argument, 0, 'a'},
		{"platform", required_argument, 0, 'p'},
	  {0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "i:leo:a:p:", long_options, &option_index);
		if (c == -1) break;
		switch (c)
			{
			case 'l':
			  options.doList = true;
				break;

			case 'e':
				options.doExtract = true;
				break;

			case 'i':
				options.inputFileName = optarg;
				break;

			case 'o':
				options.outputFileName = optarg;
				break;

			case 'a':
				options.newAppId = optarg;
				break;

			case 'p':
				if (strcmp(optarg, "pc") == 0) {
					options.targetPlatform = PLATFORM_PC;
				} else if (strcmp(optarg, "mac") == 0) {
					options.targetPlatform = PLATFORM_MAC;
				} else {
					printf("Error: Unknown/unsupported platform '%s'\n", optarg);
					exit(1);
				}
				break;

			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort();
			}
	}

	options.verbose_flag = verbose_flag;

	if (options.inputFileName == NULL) {
		printf("No inputfile specified\n");
		usage();
		exit(1);
	}

	if (!psarc.read(options.inputFileName)) {
		printf("Unable to open archive '%s'\n", options.inputFileName);
		exit(1);
	}

	if (options.doList) {
		psarc.displayFileList();
	}

	if (options.doExtract) {
		psarc.extractAllFiles();
	}

	if (options.outputFileName != NULL) {
		psarc.write(options);
	}

	return EXIT_SUCCESS;
}

#ifndef OPTIONS_H__
#define OPTIONS_H__

#include "psarc_platform.h"

class Options {
public:
  Options()
    : verbose_flag(false)
    , inputFileName(NULL)
    , outputFileName(NULL)
    , newAppId(NULL)
    , doList(false)
    , doExtract(false)
    , targetPlatform(PLATFORM_NONE)
  {}

  bool verbose_flag;
	char *inputFileName;
	char *outputFileName;
	char *newAppId;
	bool doList;
	bool doExtract;
	platform targetPlatform;
};


#endif // OPTIONS_H__

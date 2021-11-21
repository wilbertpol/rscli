/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#ifndef PSARC_H__
#define PSARC_H__

#include <vector>
#include "file.h"
#include "options.h"
#include "psarc_header.h"
#include "psarc_entry.h"


class PSARC {
public:
	PSARC();
	~PSARC();

	bool read(const char *arcName);
	void displayHeader();
	void displayFileList();
	void extractAllFiles();
	bool write(Options& options);

private:
	static const uint8_t NEW_LINE = 0x0a;

	void readEntry(Entry& entry, uint32_t *zBlocks, uint32_t cBlockSize);
	void parseTocEntry(Entry& entry);
	void extractRawEntryData(Entry& entry, char *baseDir);
	void decryptEntry(Entry& entry);
	void encryptEntry(Entry& entry, platform targetPlatform);
	platform determineSngOriginalPlatform(uint8_t *data);
	void setNewAppId(const char *newAppId);
	void writeBlock(File& stream, uint8_t *dataToWrite, uint8_t *zBlocks, uint32_t zBlock, uint64_t *zOffset, uint32_t blockSize);

	File _f;
	uint8_t *_buffer;

	Header m_header;
	std::vector<Entry> m_entries;
	char *baseDir;
};

#endif // PSARC_H__

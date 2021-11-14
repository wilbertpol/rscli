/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#ifndef PSARC_H__
#define PSARC_H__

#include <vector>
#include "file.h"
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

private:
	void readEntry(Entry& entry, uint32_t *zBlocks, uint32_t cBlockSize);
	void parseTocEntry(Entry& entry);
	void exportRawEntryData(Entry& entry, char *baseDir);

	File _f;
	uint8_t *_buffer;

	Header m_header;
	std::vector<Entry> m_entries;
	char *baseDir;
};

#endif // PSARC_H__

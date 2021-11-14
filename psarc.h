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


struct PSARC {
	File _f;
	uint8_t *_buffer;

	Header m_header;
	std::vector<Entry> m_entries;

	PSARC();
	~PSARC();

	void readEntry(Entry& entry, uint32_t *zBlocks, uint32_t cBlockSize);
	void parseTocEntry(Entry& entry);
	void writeRawData(Entry& entry, char *baseDir);
	void read(const char *arcName, uint32_t start, uint32_t end, bool header);
	void read(const char *arcName, uint32_t start, uint32_t end);
	void readHeader(const char *arcName);
};

#endif // PSARC_H__

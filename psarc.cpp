/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#include <inttypes.h>
#include "psarc.h"
#include "Rijndael.h"
#include "sys.h"

static const char PsarcKey[32] =
{
	0xC5, 0x3D, 0xB2, 0x38, 0x70, 0xA1, 0xA2, 0xF7,
	0x1C, 0xAE, 0x64, 0x06, 0x1F, 0xDD, 0x0E, 0x11,
	0x57, 0x30, 0x9D, 0xC8, 0x52, 0x04, 0xD4, 0xC5,
	0xBF, 0xDF, 0x25, 0x09, 0x0D, 0xF2, 0x57, 0x2C
};

PSARC::PSARC() {
	_buffer = (uint8_t *)malloc(600 * 1024);
}

PSARC::~PSARC() {
	_f.close();
	free(_buffer);
}


void PSARC::readEntry(Entry& entry, uint32_t *zBlocks, uint32_t cBlockSize) {
	if (entry.getLength() != 0 && entry.getData() == NULL) {
		uint8_t *data = (uint8_t *)malloc(entry.getLength());
		entry.setData(data);
		_f.seek(entry.getZOffset());
		uint32_t zIndex = entry.getZIndex();
		uint64_t writeOffset = 0;
		do {
			if (zBlocks[zIndex] == 0) {
				_f.read(data + writeOffset, cBlockSize);
				writeOffset += cBlockSize;
			} else {
				_f.read(_buffer, zBlocks[zIndex]);
				if (_buffer[0] == 0x78 && _buffer[1] == 0xda) {
					uLongf uncompressSize;
					uint32_t val = entry.getLength() - (zIndex - entry.getZIndex()) * cBlockSize;
					if (val < cBlockSize) {
						uncompressSize = (uLongf)val;
					} else {
						uncompressSize = (uLongf)cBlockSize;
					}
					uncompress(data + writeOffset, &uncompressSize, _buffer, zBlocks[zIndex]);
					writeOffset += uncompressSize;
				} else {
					memcpy(data + writeOffset, _buffer, zBlocks[zIndex]);
					writeOffset += zBlocks[zIndex];
				}
			}
			zIndex++;
		} while (writeOffset < entry.getLength());
		if (writeOffset != entry.getLength()) {
			printf("File size : %" PRId64 " bytes. Expected size: %" PRId64 " bytes\n",
				writeOffset, entry.getLength()
			);
		}
	}
}


void PSARC::parseTocEntry(Entry& entry) {
	if (entry.getId() != 0) {
		printf("Error: trying to parse an entry with id (%d) != 0 as TOC entry\n", entry.getId());
		return;
	}
	if (entry.getData() == NULL || entry.getLength() == 0) {
		printf("Error: TOC data not loaded yet\n");
		return;
	}

	uint8_t *data = entry.getData();
	uint64_t offset = 0;

	for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
		uint64_t nameStart = offset;
		uint8_t byte = data[offset++];
		uint8_t count = 1;

		while ((byte != 10) && (offset < entry.getLength())) {
			byte = data[offset++];
			count++;
		}

		if (byte == 10) {
			char *name = strndup((char *)data + nameStart, count - 1);
			m_entries.at(i).setName(name);
		} else {
			char *name = strndup((char *)data + nameStart, count);
			m_entries.at(i).setName(name);
		}
	}
	// TODO: Verify that all entries have a name
}


void PSARC::exportRawEntryData(Entry& entry, char *baseDir) {
	if (entry.getLength() != 0 && entry.getData() != NULL) {
		printf("writing %i %" PRId64 " %s\n", entry.getId(), entry.getLength(), entry.getName());

		char *subOutDirc = strdup(entry.getName());
		char *outFilec = strdup(entry.getName());

		char *subOutDir = dirname(subOutDirc);
		char *outFile = basename(outFilec);
		char *outDir;
		if (strncmp("/", entry.getName(), 1) == 0) {
			uint32_t length = strlen(baseDir) + strlen(subOutDir) + 1;
			outDir = (char *)malloc(length);
			snprintf(outDir, length, "%s%s", baseDir, subOutDir);
		} else {
			uint32_t length = strlen(baseDir) + strlen(subOutDir) + 2;
			outDir = (char *)malloc(length);
			snprintf(outDir, length, "%s/%s", baseDir, subOutDir);
		}

		mkpath(outDir, 0777);

		File stream;
		if (stream.open(outFile, outDir, "wb")) {
			stream.write(entry.getData(), entry.getLength());
		}
		stream.close();

		free(outDir);
		free(subOutDirc);
		free(outFilec);
	}
}


void PSARC::read(const char *arcName, uint32_t start, uint32_t end, const bool printHeader) {
	char *dirNamec = strdup(arcName);
	char *fileNamec = strdup(arcName);

	char *dirName = dirname(dirNamec);
	char *fileName = basename(fileNamec);

	if (_f.open(fileName, dirName)) {
		m_header.setMagicNumber(_f.readUint32BE(_buffer));
		if (m_header.isPSARC()) {
			m_header.setVersionNumber(_f.readUint32BE(_buffer));
			m_header.setCompressionMethod(_f.readUint32BE(_buffer));
			m_header.setTotalTocSize(_f.readUint32BE(_buffer));
			m_header.setTocEntrySize(_f.readUint32BE(_buffer));
			m_header.setNumFiles(_f.readUint32BE(_buffer));
			m_header.setBlockSizeAlloc(_f.readUint32BE(_buffer));
			m_header.setArchiveFlags(_f.readUint32BE(_buffer));

			printf("Header:\n");
			printf("\tmagicNumber:       %08x\n", m_header.getMagicNumber());
			printf("\tversionNumer:      %08x\n", m_header.getVersionNumber());
			printf("\tcompressionMethod: %08x\n", m_header.getCompressionMethod());
			printf("\ttotalTOCSize:      %08x\n", m_header.getTotalTocSize());
			printf("\ttocEntrySize:      %08x\n", m_header.getTocEntrySize());
			printf("\tnumFiles:          %08x\n", m_header.getNumFiles());
			printf("\tblockSizeAlloc:    %08x\n", m_header.getBlockSizeAlloc());
			printf("\tarchiveFlags:      %08x\n", m_header.getArchiveFlags());

			if (m_header.isZlib()) {
				uint8_t zType = 1;
				uint32_t i = 256;
				do {
					i *= 256;
					zType = (uint8_t)(zType + 1);
				} while (i < m_header.getBlockSizeAlloc());

				_f.seek(Header::HEADER_SIZE);
				uint32_t realTocSize = m_header.getTotalTocSize() - Header::HEADER_SIZE;
				char rawToc[m_header.getTotalTocSize()];
				if (m_header.isTocEncrypted()) {
					char encryptedToc[m_header.getTotalTocSize()];
					_f.readBytes(encryptedToc, realTocSize);
					CRijndael rijndael;

					rijndael.MakeKey(PsarcKey, CRijndael::sm_chain0, 32, 16);
  				rijndael.Decrypt(encryptedToc, rawToc, m_header.getTotalTocSize() & ~31, CRijndael::CFB);
				} else {
					_f.readBytes(rawToc, realTocSize);
				}
				uint32_t tocOffset = 0;
				m_entries.reserve(m_header.getNumFiles());
				for (uint32_t i = 0; i < m_header.getNumFiles(); i++) {
					Entry entry = Entry(i);
					char md5[16];
					for (int j = 0; j < 16; j++) {
						md5[j] = rawToc[tocOffset++];
					}
					entry.setMd5(md5);
					entry.setZIndex(READ_BE_UINT32(&rawToc[tocOffset]));
					tocOffset += 4;
					entry.setLength(READ_BE_INT40(&rawToc[tocOffset]));
					tocOffset += 5;
					entry.setZOffset(READ_BE_INT40(&rawToc[tocOffset]));
					tocOffset += 5;
					m_entries.push_back(entry);
				}

				uint32_t numBlocks = (m_header.getTotalTocSize() - (tocOffset + Header::HEADER_SIZE)) / zType;
				uint32_t *zBlocks = new uint32_t[numBlocks];
				for (uint32_t i = 0; i < numBlocks; i++) {
					switch (zType) {
						case 2:
							zBlocks[i] = READ_BE_UINT16(&rawToc[tocOffset]); tocOffset += 2;
							break;

						case 3:
							zBlocks[i] = READ_BE_INT24(&rawToc[tocOffset]); tocOffset += 3;
							break;

						case 4:
							zBlocks[i] = READ_BE_UINT32(&rawToc[tocOffset]); tocOffset += 4;
							break;
					}
				}

				char *baseDir = NULL;
				char ext[] = ".psarc";
				if (strlen(fileName) >= 6 && strncmp(fileName + strlen(fileName) - strlen(ext), ext, strlen(ext)) == 0) {
					baseDir = (char *)malloc(strlen(fileName) - strlen(ext) + 1);
					snprintf(baseDir, strlen(fileName) - strlen(ext) + 1, "%s", fileName);
				} else {
					char data[] = "_data";

					baseDir = (char *)malloc(strlen(fileName) + strlen(data) + 1);
					snprintf(baseDir, strlen(fileName) + strlen(data) + 1, "%s%s", fileName, data);
				}

				for (uint32_t i = 0; i < m_header.getNumFiles(); i++) {
					readEntry(m_entries.at(i), zBlocks, m_header.getBlockSizeAlloc());
				}
				parseTocEntry(m_entries.at(0));

				if (printHeader) {
					for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
						Entry &entry = m_entries.at(i);
						printf("%d %" PRId64 " b %s\n", entry.getId(), entry.getLength(), entry.getName());
					}
				} else {
					bool flag = true;
					if (start == 0) {
						start = 1;
						end = m_header.getNumFiles();
					} else if ((start > (m_header.getNumFiles() - 1)) || (end > (m_header.getNumFiles() - 1))) {
						flag = false;
					} else {
						end++;
					}

					if (flag) {
						for (uint32_t i = start; i < end; i++) {
							exportRawEntryData(m_entries.at(i), baseDir);
						}
					}
				}

				free(baseDir);
				delete[] zBlocks;
			}
		} else
			printf("Compression type is not zlib... Aborting.");
	}
}

void PSARC::read(const char *arcName, uint32_t start, uint32_t end) {
	read(arcName, start, end, false);
}

void PSARC::readHeader(const char *arcName) {
	read(arcName, 0, 0, true);
}

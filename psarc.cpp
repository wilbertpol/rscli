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

void PSARC::inflateEntry(uint32_t entry, uint32_t *zBlocks, uint32_t cBlockSize, char *basename, char *dirname) {
	uint64_t length = 0;

	if (entry == 0) {
		dirname = (char *)"/tmp";
		basename = (char *)"psarc.temp";
	}
	File stream;
	if (stream.open(basename, dirname, "w")) {
		if (m_entries.at(entry).getLength() != 0) {
			_f.seek(m_entries.at(entry).getZOffset());
			uint32_t zIndex = m_entries.at(entry).getZIndex();
			do {
				if (zBlocks[zIndex] == 0) {
					_f.read(_buffer, cBlockSize);
					stream.write(_buffer, cBlockSize);
				} else {
					uint16_t isGzipped = _f.readUint16BE(_buffer);
					_f.shift(-2);
					_f.read(_buffer, zBlocks[zIndex]);
					if (isGzipped == 0x78da) {
						uint8_t *uncompressData;
						uLongf uncompressSize;
						uint32_t val = m_entries.at(entry).getLength() - (zIndex - m_entries.at(entry).getZIndex()) * cBlockSize;
						if (val < cBlockSize) {
							uncompressData = (uint8_t *)malloc(val);
							uncompressSize = (uLongf)val;
						} else {
							uncompressData = (uint8_t *)malloc(cBlockSize);
							uncompressSize = (uLongf)cBlockSize;
						}
						printf("uncompressSize %0lx\n", uncompressSize);
						uncompress(uncompressData, &uncompressSize, _buffer, zBlocks[zIndex]);
						printf("uncompressSize %0lx\n", uncompressSize);
						printf("zBlocks[zIndex] %0x\n", zBlocks[zIndex]);
						stream.write(uncompressData, uncompressSize);
						free(uncompressData);
					} else {
						stream.write(_buffer, zBlocks[zIndex]);
					}
				}
				zIndex++;
			} while (stream.offset() < m_entries.at(entry).getLength());
		}

		if (entry == 0) {
			length = stream.offset();
			stream.close();

			File reader;
			reader.open(basename, dirname, "r");

			m_entries.at(0).setName((char*)"NamesBlock.bin");
			for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
				int32_t pos = reader.offset();
				uint8_t byte = reader.readByte();
				uint8_t count = 1;

				while ((byte != 10) && (reader.offset() < length)) {
					byte = reader.readByte();
					count++;
				}

				reader.seek(pos);
				if (byte == 10) {
					reader.read(_buffer, count - 1);
					char *name = strndup((char *)_buffer, count - 1);
					m_entries.at(i).setName(name);
					reader.shift(1);
				} else {
					reader.read(_buffer, count);
					char *name = strndup((char *)_buffer, count);
					m_entries.at(i).setName(name);
				}
			}

			reader.close();
			remove("/tmp/psarc.temp");
		} else {
			if (stream.offset() != m_entries.at(entry).getLength())
				printf("File size : %" PRId64 " bytes. Expected size: %" PRId64 " bytes\n", stream.offset(), m_entries.at(entry).getLength());

			stream.close();
		}
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

				inflateEntry(0, zBlocks, m_header.getBlockSizeAlloc(), NULL, NULL);

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
						mkdir(baseDir, 0777);

						for (uint32_t i = start; i < end; i++) {
							printf("%i %s\n", m_entries.at(i).getId(), m_entries.at(i).getName());

							char *subOutDirc = strdup(m_entries.at(i).getName());
							char *outFilec = strdup(m_entries.at(i).getName());

							char *subOutDir = dirname(subOutDirc);
							char *outFile = basename(outFilec);
							char *outDir;
							if (strncmp("/", m_entries.at(i).getName(), 1) == 0) {
								outDir = (char *)malloc(strlen(baseDir) + strlen(subOutDir) + 1);
								snprintf(outDir, strlen(baseDir) + strlen(subOutDir) + 1, "%s%s", baseDir, subOutDir);
							} else {
								outDir = (char *)malloc(strlen(baseDir) + strlen(subOutDir) + 2);
								snprintf(outDir, strlen(baseDir) + strlen(subOutDir) + 2, "%s/%s", baseDir, subOutDir);
							}

							mkpath(outDir, 0777);

							inflateEntry(i, zBlocks, m_header.getBlockSizeAlloc(), outFile, outDir);

							free(outDir);
							free(subOutDirc);
							free(outFilec);
						}
					}
				}

				free(baseDir);
				delete[] zBlocks;
			}
		} else
			printf("Compression type is not zlib... Aborting.");
	}

//	free(dirNamec);
//	free(fileNamec);
}

void PSARC::read(const char *arcName, uint32_t start, uint32_t end) {
	printf("read\n");
	read(arcName, start, end, false);
	printf("read done\n");
}

void PSARC::readHeader(const char *arcName) {
	printf("readHeader\n");
	read(arcName, 0, 0, true);
	printf("readHeader done\n");
}

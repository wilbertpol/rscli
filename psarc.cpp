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
	_entries = NULL;
}

PSARC::~PSARC() {
	_f.close();
	free(_buffer);

	if (_entries != NULL)
		delete _entries;
}

void PSARC::inflateEntry(uint32_t entry, uint32_t *zBlocks, uint32_t cBlockSize, char *basename, char *dirname) {
	uint64_t length = 0;

	if (entry == 0) {
		dirname = (char *)"/tmp";
		basename = (char *)"psarc.temp";
	}
	File stream;
	if (stream.open(basename, dirname, "w")) {
		if (_entries[entry]._length != 0) {
			_f.seek(_entries[entry]._zOffset);
			uint32_t zIndex = _entries[entry]._zIndex;
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
						uint32_t val = _entries[entry]._length - (zIndex - _entries[entry]._zIndex) * cBlockSize;
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
			} while (stream.offset() < _entries[entry]._length);
		}

		if (entry == 0) {
			length = stream.offset();
			stream.close();

			File reader;
			reader.open(basename, dirname, "r");

			_entries[0]._name = (char *)"NamesBlock.bin";
			for (uint32_t i = 1; i < _header.getNumFiles(); i++) {
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
					_entries[i]._name = strndup((char *)_buffer, count - 1);
					reader.shift(1);
				} else {
					reader.read(_buffer, count);
					_entries[i]._name = strndup((char *)_buffer, count);
				}
			}

			reader.close();
			remove("/tmp/psarc.temp");
		} else {
			if (stream.offset() != _entries[entry]._length)
				printf("File size : %" PRId64 " bytes. Expected size: %" PRId64 " bytes\n", stream.offset(), _entries[entry]._length);

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
		_header.setMagicNumber(_f.readUint32BE(_buffer));
		if (_header.isPSARC()) {
			_header.setVersionNumber(_f.readUint32BE(_buffer));
			_header.setCompressionMethod(_f.readUint32BE(_buffer));
			_header.setTotalTocSize(_f.readUint32BE(_buffer));
			_header.setTocEntrySize(_f.readUint32BE(_buffer));
			_header.setNumFiles(_f.readUint32BE(_buffer));
			_header.setBlockSizeAlloc(_f.readUint32BE(_buffer));
			_header.setArchiveFlags(_f.readUint32BE(_buffer));

			printf("Header:\n");
			printf("\tmagicNumber:       %08x\n", _header.getMagicNumber());
			printf("\tversionNumer:      %08x\n", _header.getVersionNumber());
			printf("\tcompressionMethod: %08x\n", _header.getCompressionMethod());
			printf("\ttotalTOCSize:      %08x\n", _header.getTotalTocSize());
			printf("\ttocEntrySize:      %08x\n", _header.getTocEntrySize());
			printf("\tnumFiles:          %08x\n", _header.getNumFiles());
			printf("\tblockSizeAlloc:    %08x\n", _header.getBlockSizeAlloc());
			printf("\tarchiveFlags:      %08x\n", _header.getArchiveFlags());

			if (_header.isZlib()) {
				uint8_t zType = 1;
				uint32_t i = 256;
				do {
					i *= 256;
					zType = (uint8_t)(zType + 1);
				} while (i < _header.getBlockSizeAlloc());

				_f.seek(Header::HEADER_SIZE);
				_entries = new Pack[_header.getNumFiles()];
				uint32_t realTocSize = _header.getTotalTocSize() - Header::HEADER_SIZE;
				char rawToc[realTocSize];
				if (_header.isTocEncrypted()) {
					char encryptedToc[_header.getTotalTocSize()];
					_f.readBytes(encryptedToc, realTocSize);
					CRijndael rijndael;

					rijndael.MakeKey(PsarcKey, CRijndael::sm_chain0, 32, 16);
  				rijndael.Decrypt(encryptedToc, rawToc, _header.getTotalTocSize() & ~31, CRijndael::CFB);
				} else {
					_f.readBytes(rawToc, realTocSize);
				}
				uint32_t tocOffset = 0;
				for (uint32_t i = 0; i < _header.getNumFiles(); i++) {
					_entries[i]._id = i;
					for (int j = 0; j < 16; j++) {
						_entries[i]._md5[j] = rawToc[tocOffset++];
					}
					_entries[i]._zIndex = READ_BE_UINT32(&rawToc[tocOffset]); tocOffset += 4;
					_entries[i]._length = READ_BE_INT40(&rawToc[tocOffset]); tocOffset += 5;
					_entries[i]._zOffset = READ_BE_INT40(&rawToc[tocOffset]); tocOffset += 5;
					_entries[i]._name = NULL;
					_entries[i]._data = NULL;
				}

				uint32_t numBlocks = (_header.getTotalTocSize() - (tocOffset + Header::HEADER_SIZE)) / zType;
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

				inflateEntry(0, zBlocks, _header.getBlockSizeAlloc(), NULL, NULL);

				if (printHeader) {
					for (uint32_t i = 1; i < _header.getNumFiles(); i++) {
						printf("%d %" PRId64 " b %s\n", i, _entries[i]._length, _entries[i]._name);
					}
				} else {
					bool flag = true;
					if (start == 0) {
						start = 1;
						end = _header.getNumFiles();
					} else if ((start > (_header.getNumFiles() - 1)) || (end > (_header.getNumFiles() - 1))) {
						flag = false;
					} else {
						end++;
					}

					if (flag) {
						mkdir(baseDir, 0777);

						for (uint32_t i = start; i < end; i++) {
							printf("%i %s\n", _entries[i]._id, _entries[i]._name);

							char *subOutDirc = strdup(_entries[i]._name);
							char *outFilec = strdup(_entries[i]._name);

							char *subOutDir = dirname(subOutDirc);
							char *outFile = basename(outFilec);
							char *outDir;
							if (strncmp("/", _entries[i]._name, 1) == 0) {
								outDir = (char *)malloc(strlen(baseDir) + strlen(subOutDir) + 1);
								snprintf(outDir, strlen(baseDir) + strlen(subOutDir) + 1, "%s%s", baseDir, subOutDir);
							} else {
								outDir = (char *)malloc(strlen(baseDir) + strlen(subOutDir) + 2);
								snprintf(outDir, strlen(baseDir) + strlen(subOutDir) + 2, "%s/%s", baseDir, subOutDir);
							}

							mkpath(outDir, 0777);

							inflateEntry(i, zBlocks, _header.getBlockSizeAlloc(), outFile, outDir);

							free(outDir);
							free(subOutDirc);
							free(outFilec);
							free(_entries[i]._name);
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

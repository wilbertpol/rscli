/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#include <inttypes.h>
#include "psarc.h"

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
printf("entries length != 0\n");
			_f.seek(_entries[entry]._zOffset);
printf("After seek\n");
			uint32_t zIndex = _entries[entry]._zIndex;
			do {
printf("zIndex = %08x\n", zIndex);
				if (zBlocks[zIndex] == 0) {
printf("Before read 1\n");
					_f.read(_buffer, cBlockSize);
printf("Before write 1\n");
					stream.write(_buffer, cBlockSize);
printf("After write 1\n");
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
printf("Befure uncompress\n");
						uncompress(uncompressData, &uncompressSize, _buffer, zBlocks[zIndex]);
printf("After uncompress, before write\n");
						stream.write(uncompressData, uncompressSize);
printf("After write 2\n");
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
			for (uint32_t i = 1; i < _numEntries; i++) {
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

void PSARC::read(const char *arcName, uint32_t start, uint32_t end, bool header) {
	char *dirNamec = strdup(arcName);
	char *fileNamec = strdup(arcName);

	char *dirName = dirname(dirNamec);
	char *fileName = basename(fileNamec);

	if (_f.open(fileName, dirName)) {
		_header.magicNumber = _f.readUint32BE(_buffer);
		if (_header.magicNumber == kPSARCMagicNumber) {
			_header.versionNumber = _f.readUint32BE(_buffer);
			_header.compressionMethod = _f.readUint32BE(_buffer);
			_header.totalTOCSize = _f.readUint32BE(_buffer);
			_header.tocEntrySize = _f.readUint32BE(_buffer);
			_header.numFiles = _f.readUint32BE(_buffer);
			_header.blockSizeAlloc = _f.readUint32BE(_buffer);
			_header.archiveFlags = _f.readUint32BE(_buffer);
			if (_header.compressionMethod == 0x7a6c6962) {
				printf("Header:\n");
				printf("\tmagicNumber:       %08x\n", _header.magicNumber);
				printf("\tversionNumer:      %08x\n", _header.versionNumber);
				printf("\tcompressionMethod: %08x\n", _header.compressionMethod);
				printf("\ttotalTOCSize:      %08x\n", _header.totalTOCSize);
				printf("\ttocEntrySize:      %08x\n", _header.tocEntrySize);
				printf("\tnumFiles:          %08x\n", _header.numFiles);
				printf("\tblockSizeAlloc:    %08x\n", _header.blockSizeAlloc);
				printf("\tarchiveFlags:      %08x\n", _header.archiveFlags);

				uint8_t zType = 1;
				uint32_t i = 256;
				do {
					i *= 256;
					zType = (uint8_t)(zType + 1);
				} while (i < _header.blockSizeAlloc);

				_f.seek(HEADER_SIZE);
				_entries = new Pack[_numEntries];
				for (uint32_t i = 0; i < _numEntries; i++) {
					_f.shift(16);

					_entries[i]._id = i;
					_entries[i]._zIndex = _f.readUint32BE(_buffer);
					_entries[i]._length = _f.readInt40BE(_buffer);
					_entries[i]._zOffset = _f.readInt40BE(_buffer);
					printf("%d: zIndex = %08x, zIndex = %08x, length = %llu\n",
						i, _entries[i]._id, _entries[i]._zIndex, _entries[i]._length
						);
				}

				uint32_t numBlocks = (_header.totalTOCSize - (uint32_t)_f.offset()) / zType;
				uint32_t *zBlocks = new uint32_t[numBlocks];
				for (uint32_t i = 0; i < numBlocks; i++) {
					switch (zType) {
						case 2:
							zBlocks[i] = _f.readUint16BE(_buffer);
							break;

						case 3:
							zBlocks[i] = _f.readInt24BE(_buffer);
							break;

						case 4:
							zBlocks[i] = _f.readUint32BE(_buffer);
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

				inflateEntry(0, zBlocks, _header.blockSizeAlloc, NULL, NULL);

				if (header) {
					char ext[] = ".txt";
					char *outList = (char *)malloc(strlen(fileName) + strlen(ext) + 1);
					snprintf(outList, strlen(fileName) + strlen(ext) + 1, "%s%s", fileName, ext);

					File list;
					if (list.open(outList, ".", "w")) {
						for (uint32_t i = 1; i < _numEntries; i++) {
							char msg[512];

							if (_entries[i]._length < 0x400L)
								sprintf(msg, "%d %" PRId64 " b %s\n", i, _entries[i]._length, _entries[i]._name);
							else if (_entries[i]._length < 0x100000L)
								sprintf(msg, "%d %1.2f Kb %s\n", i, _entries[i]._length / 1024.0, _entries[i]._name);
							else if (_entries[i]._length < 0x40000000L)
								sprintf(msg, "%d %1.2f Mb %s\n", i, _entries[i]._length / 1048576.0, _entries[i]._name);
							else
								sprintf(msg, "%d %1.2f Gb %s\n", i, _entries[i]._length / 1073741824.0, _entries[i]._name);

							list.write(msg, strlen(msg));
						}

						list.close();
					}

					free(outList);
				} else {
					bool flag = true;
					if (start == 0) {
						start = 1;
						end = _numEntries;
					} else if ((start > (_numEntries - 1)) || (end > (_numEntries - 1))) {
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

							inflateEntry(i, zBlocks, _header.blockSizeAlloc, outFile, outDir);

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

	free(dirNamec);
	free(fileNamec);
}

void PSARC::read(const char *arcName, uint32_t start, uint32_t end) {
	read(arcName, start, end, false);
}

void PSARC::readHeader(const char *arcName) {
	read(arcName, 0, 0, true);
}

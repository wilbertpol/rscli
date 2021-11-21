/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#include <cstdio>
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


static const char SngKeyMac[32] =
{
		0x98, 0x21, 0x33, 0x0E, 0x34, 0xB9, 0x1F, 0x70,
		0xD0, 0xA4, 0x8C, 0xBD, 0x62, 0x59, 0x93, 0x12,
		0x69, 0x70, 0xCE, 0xA0, 0x91, 0x92, 0xC0, 0xE6,
		0xCD, 0xA6, 0x76, 0xCC, 0x98, 0x38, 0x28, 0x9D
};


static const char SngKeyPC[32] =
{
		0xCB, 0x64, 0x8D, 0xF3, 0xD1, 0x2A, 0x16, 0xBF,
		0x71, 0x70, 0x14, 0x14, 0xE6, 0x96, 0x19, 0xEC,
		0x17, 0x1C, 0xCA, 0x5D, 0x2A, 0x14, 0x2E, 0x3E,
		0x59, 0xDE, 0x7A, 0xDD, 0xA1, 0x8A, 0x3A, 0x30
};

#define MAX_ENCRYPTION_BLOCK_SIZE 32


PSARC::PSARC() {
	_buffer = (uint8_t *)malloc(600 * 1024);
	baseDir = NULL;
}

PSARC::~PSARC() {
	_f.close();
	free(_buffer);
	if (baseDir != NULL)
		free(baseDir);
}


void PSARC::readEntry(Entry& entry, uint32_t *zBlocks, uint32_t cBlockSize) {
	if (entry.getLength() != 0 && entry.getData() == NULL) {
		uint8_t *data = (uint8_t *)malloc(entry.getLength() + MAX_ENCRYPTION_BLOCK_SIZE);
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


void PSARC::decryptEntry(Entry& entry) {
	if (entry.getLength() > 8 && entry.getData() != NULL && entry.getName() != NULL) {
		uint8_t *data = entry.getData();
		if (entry.hasExtension(".sng")) {
			if (READ_LE_UINT32(data) == 0x4a) {
				if (READ_LE_UINT32(data + 4) == 0x03) {
					entry.setEncrypted(true);
					entry.setOriginalPlatform(determineSngOriginalPlatform(data));
					const char *key = NULL;
					if (entry.getOriginalPlatform() == PLATFORM_PC) {
						key = SngKeyPC;
					}
					if (entry.getOriginalPlatform() == PLATFORM_MAC) {
						key = SngKeyMac;
					}
					if (key == NULL) {
						printf("Unable to determine original platform for '%s'\n", entry.getName());
						return;
					}
					uint64_t offset = 8;
					uint64_t writeOffset = 0;
					uint8_t blockLength = 16;
					uint8_t *decryptedSng = (uint8_t *)malloc(entry.getLength() + MAX_ENCRYPTION_BLOCK_SIZE);
					entry.setDecryptedLength(entry.getLength());
					entry.setDecryptedData(decryptedSng);
					char iv[16];
					for (int i = 0; i < 16; i++) {
						iv[i] = data[offset++];
					}
					CRijndael rijndael;

					do {
						rijndael.MakeKey(key, iv, 32, blockLength);
  					rijndael.Decrypt((char *)data + offset, (char *)decryptedSng + writeOffset, blockLength, CRijndael::CFB);
						offset += blockLength;
						writeOffset += blockLength;
						bool carry = true;
						for (int j = 15; j >= 0 && carry; j--) {
								carry = ((iv[j] = (iv[j] + 1)) == 0);
						}
					} while (offset < entry.getLength());
					uLongf uncompressedSize = READ_LE_UINT32(decryptedSng);
					uint8_t *uncompressedData = (uint8_t *)malloc(uncompressedSize);
					entry.setDecompressedLength(uncompressedSize);
					entry.setDecompressedData(uncompressedData);
					uncompress(uncompressedData, &uncompressedSize, decryptedSng + 4, entry.getLength() - 28);
				}
			}
		}
	}
}


void PSARC::encryptEntry(Entry& entry, platform targetPlatform) {
	if (entry.getDecryptedLength() > 8 + 16 && entry.getDecryptedData() != NULL && entry.isEncrypted()) {
		uint8_t *decryptedData = entry.getDecryptedData();
		uint8_t *data = entry.getData();
		const char *key = NULL;
		if (targetPlatform == PLATFORM_PC) {
			key = SngKeyPC;
		}
		if (targetPlatform == PLATFORM_MAC) {
			key = SngKeyMac;
		}
		if (key == NULL) {
			printf("Unable to determine target platform encrypted key for '%s'\n", entry.getName());
			return;
		}
		uint64_t offset = 8;
		uint64_t readOffset = 0;
		uint8_t blockLength = 16;
		char iv[16];
		for (int i = 0; i < 16; i++) {
			iv[i] = decryptedData[offset++];
		}
		CRijndael rijndael;

		do {
			rijndael.MakeKey(key, iv, 32, blockLength);
			rijndael.Encrypt((char *)decryptedData + readOffset, (char *)data + offset, blockLength, CRijndael::CFB);
			offset += blockLength;
			readOffset += blockLength;
			bool carry = true;
			for (int j = 15; j >= 0 && carry; j--) {
					carry = ((iv[j] = (iv[j] + 1)) == 0);
			}
		} while (readOffset < entry.getDecryptedLength());
	}
}


platform PSARC::determineSngOriginalPlatform(uint8_t *data) {
	uint64_t offset = 8;
	uint8_t decryptedSng[16];
	char iv[16];
	for (int i = 0; i < 16; i++) {
		iv[i] = data[offset++];
	}
	CRijndael rijndael;

	rijndael.MakeKey(SngKeyPC, iv, 32, 16);
	rijndael.Decrypt((char *)data + offset, (char *)decryptedSng, 16, CRijndael::CFB);
//	printf("Decrypted: ");
//	for (int i = 0; i < 16; i++) {
//		printf("%02x ", decryptedSng[i]);
//	}
//	printf("\n");
	if (decryptedSng[4] == 0x78 && decryptedSng[5] == 0xda) {
		return PLATFORM_PC;
	}
	rijndael.MakeKey(SngKeyMac, iv, 32, 16);
	rijndael.Decrypt((char *)data + offset, (char *)decryptedSng, 16, CRijndael::CFB);
//	printf("Decrypted: ");
//	for (int i = 0; i < 16; i++) {
//		printf("%02x ", decryptedSng[i]);
//	}
//	printf("\n");
	if (decryptedSng[4] == 0x78 && decryptedSng[5] == 0xda) {
		return PLATFORM_MAC;
	}
	return PLATFORM_UNKNOWN;
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

		while ((byte != NEW_LINE) && (offset < entry.getLength())) {
			byte = data[offset++];
			count++;
		}

		if (byte == NEW_LINE) {
			char *name = strndup((char *)data + nameStart, count - 1);
			m_entries.at(i).setName(name);
		} else {
			char *name = strndup((char *)data + nameStart, count);
			m_entries.at(i).setName(name);
		}
	}
	// TODO: Verify that all entries have a name
}


void PSARC::extractRawEntryData(Entry& entry, char *baseDir) {
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

		// write raw
		if (stream.open(outFile, outDir, "wb")) {
				stream.write(entry.getData(), entry.getLength());
		}
		stream.close();
		// write decrypted
		if (entry.isEncrypted() && entry.getDecryptedLength() > 0 && entry.getDecryptedData() != NULL) {
			char decrypted[] = ".decrypted";
			uint32_t length = strlen(outFile) + strlen(decrypted) + 1;
			char *decryptedFileName = (char *)malloc(length);
			snprintf(decryptedFileName, length, "%s%s", outFile, decrypted);
			if (stream.open(decryptedFileName, outDir, "wb")) {
				stream.write(entry.getDecryptedData(), entry.getDecryptedLength());
			}
			stream.close();
			free(decryptedFileName);
			// write decompressed
			if (entry.getDecompressedLength() > 0 && entry.getDecompressedData() != NULL) {
				char decompressed[] = ".decompressed";
				uint32_t length = strlen(outFile) + strlen(decompressed) + 1;
				char *decompressedFileName = (char *)malloc(length);
				snprintf(decompressedFileName, length, "%s%s", outFile, decompressed);
				if (stream.open(decompressedFileName, outDir, "wb")) {
					stream.write(entry.getDecompressedData(), entry.getDecompressedLength());
				}
				stream.close();
				free(decompressedFileName);
			}
		}
/*
		File stream;
		if (stream.open(outFile, outDir, "wb")) {
			if (entry.isEncrypted() && entry.getDecompressedLength() > 0 && entry.getDecompressedData() != NULL) {
				// Write decrypted decompressed data
				stream.write(entry.getDecompressedData(), entry.getDecompressedLength());
			} else if (entry.isEncrypted() && entry.getDecryptedLength() > 0 && entry.getDecryptedData() != NULL) {
				// Write decrypted data
				stream.write(entry.getDecryptedData(), entry.getDecryptedLength());
			} else {
				// Write raw data
				stream.write(entry.getData(), entry.getLength());
			}
		}
		stream.close();
*/
		free(outDir);
		free(subOutDirc);
		free(outFilec);
	}
}


bool PSARC::read(const char *arcName) {
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

			if (m_header.isZlib()) {
				m_header.setZType(1);
				for (uint64_t i = 0x100; i < m_header.getBlockSizeAlloc(); i <<= 8) {
					m_header.setZType(m_header.getZType() + 1);
				}

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

				uint32_t numBlocks = (m_header.getTotalTocSize() - (tocOffset + Header::HEADER_SIZE)) / m_header.getZType();
				uint32_t *zBlocks = new uint32_t[numBlocks];
				for (uint32_t i = 0; i < numBlocks; i++) {
					switch (m_header.getZType()) {
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
					if (i == 0) {
						parseTocEntry(m_entries.at(0));
					} else {
						decryptEntry(m_entries.at(i));
					}
				}

				delete[] zBlocks;
				return true;
			} else {
				printf("Compression type is not zlib... Aborting.");
				return false;
			}
		} else {
			printf("Is not a PSARC file... Aborting.");
			return false;
		}
		return true;
	} else {
		return false;
	}
}


void PSARC::writeBlock(File& stream, uint8_t *dataToWrite, uint8_t *zBlocks, uint32_t zBlock, uint64_t *zOffset, uint32_t blockSize) {
	// - For each block, compress where possible and write the data,
	//   write block size to zBlock data/TOC space
	// TODO Attempt to gzip block
	uint8_t *zipBuffer = (uint8_t *)malloc(blockSize);
	uLongf zipBufferSize = blockSize;
	if (compress2(zipBuffer, &zipBufferSize, dataToWrite, blockSize, Z_BEST_COMPRESSION) == Z_OK) {
		// Write compressed block
		stream.write(zipBuffer, zipBufferSize);
		switch (m_header.getZType()) {
			case 2:
				WRITE_BE_UINT16(zBlocks + m_header.getZType() * zBlock, zipBufferSize);
				break;

			case 3:
				WRITE_BE_INT24(zBlocks + m_header.getZType() * zBlock, zipBufferSize);
				break;

			case 4:
				WRITE_BE_UINT32(zBlocks + m_header.getZType() * zBlock, zipBufferSize);
				break;
		}
		*zOffset += zipBufferSize;
	} else {
		// Compression failed, write block as-is
		stream.write(dataToWrite, blockSize);
		switch (m_header.getZType()) {
			case 2:
				WRITE_BE_UINT16(zBlocks + m_header.getZType() * zBlock, blockSize);
				break;

			case 3:
				WRITE_BE_INT24(zBlocks + m_header.getZType() * zBlock, blockSize);
				break;

			case 4:
				WRITE_BE_UINT32(zBlocks + m_header.getZType() * zBlock, blockSize);
				break;
		}
		*zOffset += blockSize;
	}
	free(zipBuffer);
}


bool PSARC::write(Options& options) {
	if (options.newAppId != NULL) {
		setNewAppId(options.newAppId);
	}

	char *dirNamec = strdup(options.outputFileName);
	char *fileNamec = strdup(options.outputFileName);

	char *dirName = dirname(dirNamec);
	char *fileName = basename(fileNamec);
	char tmp[] = "_tmp";

	char *fileNameTemp = (char *)malloc(strlen(fileName) + strlen(tmp) + 1);
	snprintf(fileNameTemp, strlen(fileName) + strlen(tmp) + 1, "%s%s", fileName, tmp);

	File stream;
	if (stream.open(fileNameTemp, dirName, "wb")) {
		uint8_t *tocBuffer = (uint8_t *)malloc(64 * 1024);
		// Write data
		printf("Should write some data\n");
		// TODO Encrypt files to data areas and get new file lengths (just in case)
		if (options.targetPlatform != PLATFORM_NONE) {
			for (int i = 1; i < m_header.getNumFiles(); i++) {
				Entry &entry = m_entries.at(i);
				if (entry.isEncrypted() &&
						entry.getOriginalPlatform() != PLATFORM_NONE &&
						entry.getOriginalPlatform() != options.targetPlatform) {
					// Re-encrypt
					encryptEntry(entry, options.targetPlatform);
					printf("Re-encrypt '%s'\n", entry.getName());
				}
			}
		}
		// Rebuild file name data for file #0
		// TODO For general case, for our current functionality this is not
		// needed.
		// TODO Calculate md5 for all entries

		// Build header and TOC
		uint32_t tocSize = Header::HEADER_SIZE;

		// Reserve/write TOC space
		uint32_t zBlockCount = 0;
		for (int i = 0; i < m_header.getNumFiles(); i++) {
			Entry& entry = m_entries.at(i);
			tocSize += m_header.getTocEntrySize();
			entry.setZIndex(zBlockCount);

			zBlockCount++;
			uint64_t entryLength = entry.getLength();
			while (entryLength > m_header.getBlockSizeAlloc()) {
				zBlockCount++;
				entryLength -= m_header.getBlockSizeAlloc();
			}
		}
		uint32_t zBlockStart = tocSize;
		tocSize += m_header.getZType() * zBlockCount;
		m_header.setTotalTocSize(tocSize);

		uint64_t zOffset = tocSize;
		uint32_t zBlock = 0;
		uint8_t *zBlocks = tocBuffer + zBlockStart;
		stream.seek(zOffset);
		for (int i = 0; i < m_header.getNumFiles(); i++) {
			Entry& entry = m_entries.at(i);
			entry.setZOffset(zOffset);
			entry.setZIndex(zBlock);

			uint64_t entryLength = entry.getLength();
			uint8_t *dataToWrite = entry.getData();
			// Split data into blocks
			while (entryLength > m_header.getBlockSizeAlloc()) {
				// write BlockSizeAlloc bytes
				writeBlock(stream, dataToWrite, zBlocks, zBlock, &zOffset, m_header.getBlockSizeAlloc());
				dataToWrite += m_header.getBlockSizeAlloc();
				zBlock++;
				entryLength -= m_header.getBlockSizeAlloc();
			}
			// write entryLength bytes
			writeBlock(stream, dataToWrite, zBlocks, zBlock, &zOffset, entryLength);
			zBlock++;
			// For each file:
			// - Store offset in TOC
			// Remember offset for start of next file
		}

		uint32_t tocOffset = 0;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getMagicNumber()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getVersionNumber()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getCompressionMethod()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getTotalTocSize()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getTocEntrySize()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getNumFiles()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getBlockSizeAlloc()); tocOffset += 4;
		WRITE_BE_UINT32(tocBuffer + tocOffset, m_header.getArchiveFlags()); tocOffset += 4;
		for (int i = 0; i < m_header.getNumFiles(); i++) {
			Entry& entry = m_entries.at(i);
			for (int j = 0; j < 16; j++) {
				tocBuffer[tocOffset++ + j] = entry.getMd5()[j];
			}
			WRITE_BE_UINT32(tocBuffer + tocOffset, entry.getZIndex()); tocOffset += 4;
			WRITE_BE_INT40(tocBuffer + tocOffset, entry.getLength()); tocOffset += 5;
			WRITE_BE_INT40(tocBuffer + tocOffset, entry.getZOffset()); tocOffset += 5;
		}

		if (m_header.isTocEncrypted()) {
			// TODO encrypt header
			printf("encrypt toc\n");
			char encryptedToc[m_header.getTotalTocSize()];
			CRijndael rijndael;

			rijndael.MakeKey(PsarcKey, CRijndael::sm_chain0, 32, 16);
			rijndael.Encrypt((const char *)tocBuffer + 32, encryptedToc, m_header.getTotalTocSize() & ~31, CRijndael::CFB);
			for (int i = 0; i < 32; i++) {
				printf("%02x ", (uint8_t)encryptedToc[i]);
			}
			printf("\n");
			printf("tocOffset = %04x\n", tocOffset);
			for (uint32_t i = 32; i < m_header.getTotalTocSize(); i++) {
				tocBuffer[i] = encryptedToc[i - 32];
			}
		}
		stream.seek(0);
		stream.write(tocBuffer, tocSize);
		printf("zBlockCount = %d\n", zBlockCount);

		free(tocBuffer);
	}
	stream.close();

	// TODO Move file fileNameTemp to fileName
	if (std::rename(fileNameTemp, fileName) < 0) {
		free(fileNameTemp);
		printf("Unable to rename output file\n");
		return false;
	}

	free(fileNameTemp);
	return true;
}


void PSARC::setNewAppId(const char *newAppId) {
	for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
		if (strcmp(m_entries.at(i).getName(), "appid.appid") == 0) {
			printf("entry %d is appid.appid\n", i);
			char *newData = new char[strlen(newAppId)];
			for (int i = 0; i < strlen(newAppId); i++) {
				newData[i] = newAppId[i];
			}
			free(m_entries.at(i).getName());
			m_entries.at(i).setName(newData);
			m_entries.at(i).setLength(strlen(newAppId));
		}
	}
}


void PSARC::extractAllFiles() {
	for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
		extractRawEntryData(m_entries.at(i), baseDir);
	}
}


void PSARC::displayHeader() {
	printf("Header:\n");
	printf("\tmagicNumber:       %08x\n", m_header.getMagicNumber());
	printf("\tversionNumer:      %08x\n", m_header.getVersionNumber());
	printf("\tcompressionMethod: %08x\n", m_header.getCompressionMethod());
	printf("\ttotalTOCSize:      %08x\n", m_header.getTotalTocSize());
	printf("\ttocEntrySize:      %08x\n", m_header.getTocEntrySize());
	printf("\tnumFiles:          %08x\n", m_header.getNumFiles());
	printf("\tblockSizeAlloc:    %08x\n", m_header.getBlockSizeAlloc());
	printf("\tarchiveFlags:      %08x\n", m_header.getArchiveFlags());
}


void PSARC::displayFileList() {
	for (uint32_t i = 1; i < m_header.getNumFiles(); i++) {
		Entry &entry = m_entries.at(i);
		printf("%d %" PRId64 "b %s\n", entry.getId(), entry.getLength(), entry.getName());
	}
}

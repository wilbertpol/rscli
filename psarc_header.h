#ifndef PSARC_HEADER_H__
#define PSARC_HEADER_H__


class Header {
public:
  static const uint32_t PSARC_MAGIC_NUMBER = 0x50534152; // "PSAR"
  static const uint32_t VERSION_1_4 = 0x00010004; // 1.4
  static const uint32_t COMPRESSION_ZLIB = 0x7A6C6962; // "zlib"
  static const uint32_t COMPRESSION_LZMA = 0x6C7A6C61; // "lzma"
  static const uint32_t HEADER_SIZE = 0x20;
  static const uint32_t ENCRYPTED = 0x00000004;

  Header()
    : magicNumber(PSARC_MAGIC_NUMBER)
    , versionNumber(VERSION_1_4)
    , compressionMethod(COMPRESSION_ZLIB)
    , totalTocSize(0)
    , tocEntrySize(30)
    , numFiles(0)
    , blockSizeAlloc(0x00010000)
    , archiveFlags(0)
  {}

  void setMagicNumber(uint32_t magicNumber) { this->magicNumber = magicNumber; }
  uint32_t getMagicNumber() const { return magicNumber; }

  void setVersionNumber(uint32_t versionNumber) { this->versionNumber = versionNumber; }
  uint32_t getVersionNumber() const { return versionNumber; }

  void setCompressionMethod(uint32_t compressionMethod) { this->compressionMethod = compressionMethod; }
  uint32_t getCompressionMethod() const { return compressionMethod; }

  void setTotalTocSize(uint32_t totalTocSize) { this->totalTocSize = totalTocSize; }
  uint32_t getTotalTocSize() const { return totalTocSize; }

  void setTocEntrySize(uint32_t tocEntrySize) { this->tocEntrySize = tocEntrySize; }
  uint32_t getTocEntrySize() const { return tocEntrySize; }

  void setNumFiles(uint32_t numFiles) { this->numFiles = numFiles; }
  uint32_t getNumFiles() const { return numFiles; }

  void setBlockSizeAlloc(uint32_t blockSizeAlloc) { this->blockSizeAlloc = blockSizeAlloc; }
  uint32_t getBlockSizeAlloc() const { return blockSizeAlloc; }

  void setArchiveFlags(uint32_t archiveFlags) { this->archiveFlags = archiveFlags; }
  uint32_t getArchiveFlags() const { return archiveFlags; }

  bool isPSARC() const { return magicNumber == PSARC_MAGIC_NUMBER; }
  bool isZlib() const { return compressionMethod == COMPRESSION_ZLIB; }
  bool isLzma() const { return compressionMethod == COMPRESSION_LZMA; }
  bool isTocEncrypted() const { return archiveFlags & ENCRYPTED; }

private:
  uint32_t magicNumber;
	uint32_t versionNumber;
	uint32_t compressionMethod;
	uint32_t totalTocSize;
	uint32_t tocEntrySize;
	uint32_t numFiles;
	uint32_t blockSizeAlloc;
	uint32_t archiveFlags;
};

#endif // PSARC_HEADER_H__

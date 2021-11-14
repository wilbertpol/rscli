#ifndef PSARC_ENTRY_H__
#define PSARC_ENTRY_H__

#include "psarc_platform.h"

typedef enum platform {
  PLATFORM_UNKNOWN,
  PLATFORM_MAC,
  PLATFORM_PC
} platform;


class Entry {
public:
  Entry(uint32_t id)
    : id(id)
    , length(0)
    , name(NULL)
    , zIndex(0)
    , zOffset(0)
    , data(NULL)
    , encrypted(false)
    , originalPlatform(PLATFORM_UNKNOWN)
    , decryptedLength(0)
    , decryptedData(NULL)
    {}

  ~Entry() {
     if (data != NULL) {
       delete data;
       data = NULL;
     }
     if (decryptedData != NULL) {
       delete decryptedData;
       decryptedData = NULL;
     }
  }

  uint32_t getId() const { return id; }
  void setId(uint32_t id) { this->id = id; }

  uint64_t getLength() const { return length; }
  void setLength(uint64_t length) { this->length = length; }

  char* getName() const { return name; }
  void setName(char *name) { this->name = name; }

  uint32_t getZIndex() const { return zIndex; }
  void setZIndex(uint32_t zIndex) { this->zIndex = zIndex; }

  uint64_t getZOffset() const { return zOffset; }
  void setZOffset(uint64_t zOffset) { this->zOffset = zOffset; }

  char const* getMd5() const { return md5; }
  void setMd5(char* md5) { for (int i = 0; i < 16; i++) this->md5[i] = md5[i]; }

  uint8_t* getData() const { return data; }
  void setData(uint8_t* data) { this->data = data; }

  bool isEncrypted() const { return encrypted; }
  void setEncrypted(bool encrypted) { this->encrypted = encrypted; }

  platform getOriginalPlatform() const { return originalPlatform; }
  void setOriginalPlatform(platform originalPlatform) { this->originalPlatform = originalPlatform; }

  uint64_t getDecryptedLength() const { return decryptedLength; }
  void setDecryptedLength(uint64_t decryptedLength) { this->decryptedLength = decryptedLength; }

  uint8_t* getDecryptedData() const { return decryptedData; }
  void setDecryptedData(uint8_t *decryptedData) { this->decryptedData = decryptedData; }

private:
	uint32_t id;
	uint64_t length;
	char *name;
	uint32_t zIndex;
	uint64_t zOffset;
	char md5[16];
	uint8_t *data;
  bool encrypted;
  platform originalPlatform;
  uint64_t decryptedLength;
  uint8_t *decryptedData;
};

#endif // PSARC_ENTRY_H__

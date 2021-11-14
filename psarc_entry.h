#ifndef PSARC_ENTRY_H__
#define PSARC_ENTRY_H__


class Entry {
public:
  Entry(uint32_t id)
    : id(id)
    , length(0)
    , name(NULL)
    , zIndex(0)
    , zOffset(0)
    , data(NULL)
    {}

  ~Entry() {
     if (data != NULL) {
       delete data;
       data = NULL;
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

private:
	uint32_t id;
	uint64_t length;
	char *name;
	uint32_t zIndex;
	uint64_t zOffset;
	char md5[16];
	uint8_t *data;
};

#endif // PSARC_ENTRY_H__

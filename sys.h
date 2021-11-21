/*
 * Open PSARC PS3 extractor
 * Copyright (C) 2011-2018 Matthieu Milan
 */

#ifndef SYS_H__
#define SYS_H__

#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>


inline uint16_t READ_BE_UINT16(const uint8_t *ptr) {
	return (ptr[0] << 8) | ptr[1];
}

inline uint16_t READ_BE_UINT16(const char *ptr) {
	return READ_BE_UINT16((uint8_t *) ptr);
}


inline uint32_t READ_BE_INT24(const uint8_t *ptr) {
	return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

inline uint32_t READ_BE_INT24(const char *ptr) {
	return READ_BE_INT24((uint8_t *) ptr);
}


inline uint32_t READ_LE_UINT32(const uint8_t *ptr) {
	return (ptr[3] << 24) | (ptr[2] << 16) | (ptr[1] << 8) | ptr[0];
}


inline uint32_t READ_BE_UINT32(const uint8_t *ptr) {
	return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

inline uint32_t READ_BE_UINT32(const char *ptr) {
	return READ_BE_UINT32((uint8_t*)ptr);
}

inline uint64_t READ_BE_INT40(const uint8_t *ptr) {
	uint64_t res = ptr[4] | (0x100L * ptr[3]) | (ptr[2] * 0x10000L) | (ptr[1] * 0x1000000L) | (ptr[0] * 0x100000000LLU);
	if (ptr[0] == 0)
		res %= 0xffffffff00000000LLU;
	else
		res %= 0xfffffffe00000000LLU;
	return res;
}

inline uint64_t READ_BE_INT40(const char *ptr) {
	return READ_BE_INT40((uint8_t*)ptr);
}


inline void WRITE_BE_UINT16(uint8_t *ptr, uint16_t data) {
	ptr[0] = (data >> 8) & 0xff;
	ptr[1] = data & 0xff;
}

inline void WRITE_BE_INT24(uint8_t *ptr, uint32_t data) {
	ptr[0] = (data >> 16) & 0xff;
	ptr[1] = (data >> 8) & 0xff;
	ptr[2] = data & 0xff;
}

inline void WRITE_LE_UINT32(uint8_t *ptr, uint32_t data) {
	ptr[3] = (data >> 24) & 0xff;
	ptr[2] = (data >> 16) & 0xff;
	ptr[1] = (data >> 8) & 0xff;
	ptr[0] = data & 0xff;
}

inline void WRITE_BE_UINT32(uint8_t *ptr, uint32_t data) {
	ptr[0] = (data >> 24) & 0xff;
	ptr[1] = (data >> 16) & 0xff;
	ptr[2] = (data >> 8) & 0xff;
	ptr[3] = data & 0xff;
}

inline void WRITE_BE_INT40(uint8_t *ptr, uint64_t data) {
	ptr[0] = (data >> 32) & 0xff;
	ptr[1] = (data >> 24) & 0xff;
	ptr[2] = (data >> 16) & 0xff;
	ptr[3] = (data >> 8) & 0xff;
	ptr[4] = data & 0xff;
}


inline int mkpath(const char *s, mode_t mode){
	char *q, *r = NULL, *path = NULL, *up = NULL;
	int rv;

	rv = -1;
	if (strcmp(s, ".") == 0 || strcmp(s, "/") == 0)
		return (0);

	if ((path = strdup(s)) == NULL)
		exit(1);

	if ((q = strdup(s)) == NULL)
		exit(1);

	if ((r = dirname(q)) == NULL) {
		free(q);
		free(path);
		return (rv);
	}

	if ((up = strdup(r)) == NULL)
		exit(1);

	if ((mkpath(up, mode) == -1) && (errno != EEXIST)) {
		free(up);
		free(q);
		free(path);
		return (rv);
	}

	if ((mkdir(path, mode) == -1) && (errno != EEXIST))
		rv = -1;
	else
		rv = 0;

	free(up);
	free(q);
	free(path);
	return (rv);
}

#endif // SYS_H__

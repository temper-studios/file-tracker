#pragma once
#ifndef FIT_H
#define FIT_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>

typedef void fit_can_abort;

#define FIT_MAX_PATH 256

typedef enum FIT_Difficulty {
	FIT_DIFFICULTY_EASY = 0,
	FIT_DIFFICULTY_NORMAL,
	FIT_DIFFICULTY_HARD,
} FIT_Difficulty;

void FIT_Log(const char *format, ...);
void FIT_AbortWithMessage(const char *format, ...);

#define FIT_RELEASE_ASSERT(condition, format, ...) if (!(condition)) FIT_AbortWithMessage(format, __VA_ARGS__)
#define FIT_DEBUG_ASSERT(condition, format, ...) assert(condition)
#define FIT_SHOULD_NOT_BE_NULL(condition) FIT_DEBUG_ASSERT(condition, "")
#define FIT_ABORT_WITH_MESSAGE(format, ...) FIT_AbortWithMessage(format, __VA_ARGS__)
#define FIT_ASSERT_LOG_RETURN(condition, format, ...) if (!(condition)) { FIT_Log(format, __VA_ARGS__); return 0; }
#define FIT_LOG(format, ...) FIT_Log(format, __VA_ARGS__)

// SHA-1 constants
#define FIT_SHA1_BLOCK_SIZE 64
// this is an 160 bit number
#define FIT_SHA1_DIGEST_SIZE 20
// 20 bytes (160 bits) => 28 characters in Base64
#define FIT_BASE64_DIGEST_SIZE 64
#define FIT_BASE64_OUTPUT_STR_SIZE (4 * ((FIT_SHA1_DIGEST_SIZE + 2) / 3)) 

typedef struct FIT_Sha1Digest {
	uint8_t bytes[FIT_SHA1_DIGEST_SIZE];
} FIT_Sha1Digest;

typedef struct FIT_Base64Digest {
	char buffer[FIT_BASE64_DIGEST_SIZE];
} FIT_Base64Digest;

void FIT_DigestToBase64(FIT_Sha1Digest *input, FIT_Base64Digest *output);
void FIT_DoSha1(const char *message, size_t messageLen, FIT_Sha1Digest *digest);
fit_can_abort FIT_Sha1Test();

typedef struct FIT_Path {
	char buffer[FIT_MAX_PATH];
} FIT_Path;

int FIT_GetAbsolutePath(FIT_Path *path, const char *relativePath);
int FIT_GoUpDirectory(FIT_Path *path, FIT_Path *newPath);
int FIT_AppendPath(const FIT_Path *srce, const char *str, FIT_Path *outPath);

typedef struct FIT_FileEntry {
	char *path;
	uint32_t pathLen;
	FIT_Base64Digest hash;
	uint64_t offset;
	uint64_t offsetLen;
	char *buffer;
	uint64_t bufferLen;
	int inSnapshot;

	struct FIT_FileEntry *poolNext;
	struct FIT_FileEntry *snapNext;
	struct FIT_FileEntry *snapPrev;
	struct FIT_FileEntry *trackNext;
	struct FIT_FileEntry *trackPrev;
} FIT_FileEntry;

typedef struct FIT_Snapshot {
	FIT_FileEntry *entryHead;
	FIT_FileEntry *entryTail;
	uint32_t entryCount;
	struct FIT_Snapshot *next;
	struct FIT_Snapshot *prev;
	struct FIT_Snapshot *poolNext;
} FIT_Snapshot;

typedef struct FIT_FileStoreData {
	FIT_Snapshot *snapshotHead;
	FIT_Snapshot *snapshotTail;
	FIT_FileEntry *entryTrackingHead;
	FIT_FileEntry *entryTrackingTail;
	char *buffer;
	uint64_t bufferCount;
	uint32_t snapshotCount;
	uint32_t trackingCount;
} FIT_FileStoreData;

typedef struct FIT_Context {
	FIT_FileStoreData fsData;

	FIT_Path workingDirectory;
	FIT_Path fileStoreAbsolutePath;
	FIT_Path trackedFileAbsolutePath;
	FIT_Path filenamePath;

	FIT_FileEntry *entryHead;
	FIT_FileEntry *entryTail;
	FIT_Snapshot *snapHead;
	FIT_Snapshot *snapTail;

	FILE *fileStore;

} FIT_Context;

void FIT_ContextInit(FIT_Context *ctx);
void FIT_ContextDeinit(FIT_Context *ctx);

void *FIT_AddToSnapshotFileEntryList(FIT_Snapshot *snapshot, FIT_FileEntry *entry);
void *FIT_RemoveFromSnapshotFileEntryList(FIT_Snapshot *snapshot, FIT_FileEntry *entry);
void *FIT_AddToTrackingList(FIT_Context *ctx, FIT_FileEntry *entry);
void *FIT_RemoveFromTrackList(FIT_Context *ctx, FIT_FileEntry *entry);
void *FIT_AddToSnapshotList(FIT_Context *ctx, FIT_Snapshot *snapshot);
void *FIT_RemoveFromSnapshotList(FIT_Context *ctx, FIT_Snapshot *snap);
FIT_Snapshot *FIT_AllocateSnapshot(FIT_Context *ctx);
FIT_FileEntry *FIT_AllocateFileEntry(FIT_Context *ctx);
int FIT_IsPathInTrackingList(FIT_Context *ctx, const char *path);
int FIT_CopyFileEntry(FIT_FileEntry *dest, FIT_FileEntry *srce);
int FIT_AllocateFileContents(FILE *file, char **buffer, uint64_t *bufferLength);
int FIT_HashBuffer(FIT_Base64Digest *base64Digest, char *buffer, uint64_t bufferLen);
int FIT_SaveFileEntry(FILE *file, FIT_FileEntry *entry);
int FIT_LoadFileEntry(FILE *file, FIT_FileEntry *entry);
int FIT_SaveFileStoreFromBuffer(FIT_Context *ctx, FILE *file);
int FIT_SaveFileStoreFromFile(FIT_Context *ctx, const char *path);
int FIT_LoadFileStoreFromBuffer(FIT_Context *ctx, FILE *file);
int FIT_LoadFileStoreFromFile(FIT_Context *ctx, const char *filename);
int FIT_Run(FIT_Context *ctx, int argc, char *argv[]);

#if defined(FIT_IMPLEMENTATION)

void FIT_Log(const char *format, ...) {
	va_list args = {0};
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	fprintf(stdout, "\n");
}

void FIT_AbortWithMessage(const char *format, ...) {
	va_list args = {0};
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	exit(0);
}

// Base64 encoding lookup table
static const char FIT_BASE64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void FIT_DigestToBase64(FIT_Sha1Digest *input, FIT_Base64Digest *output) {
	FIT_SHOULD_NOT_BE_NULL(input);
	FIT_SHOULD_NOT_BE_NULL(output);

	size_t input_len = FIT_SHA1_DIGEST_SIZE;
	size_t output_len = FIT_BASE64_OUTPUT_STR_SIZE;

	FIT_DEBUG_ASSERT(output_len < FIT_BASE64_DIGEST_SIZE);

	for (size_t i = 0, j = 0; i < input_len;) {
		uint32_t octet_a = (i < input_len) ? input->bytes[i++] : 0;
		uint32_t octet_b = (i < input_len) ? input->bytes[i++] : 0;
		uint32_t octet_c = (i < input_len) ? input->bytes[i++] : 0;

		uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

		output->buffer[j++] = FIT_BASE64_TABLE[(triple >> 18) & 0x3F];
		output->buffer[j++] = FIT_BASE64_TABLE[(triple >> 12) & 0x3F];
		output->buffer[j++] = FIT_BASE64_TABLE[(triple >> 6) & 0x3F];
		output->buffer[j++] = FIT_BASE64_TABLE[triple & 0x3F];
	}

	// Add padding characters if necessary
	if (input_len % 3 == 1) {
		output->buffer[output_len - 1] = '=';
		output->buffer[output_len - 2] = '=';
	}
	else if (input_len % 3 == 2) {
		output->buffer[output_len - 1] = '=';
	}

	output->buffer[output_len] = '\0'; // Null-terminate the output string
}

void FIT_DoSha1(const char *message, size_t messageLen, FIT_Sha1Digest *digest) {
	FIT_SHOULD_NOT_BE_NULL(message);
	FIT_SHOULD_NOT_BE_NULL(digest);

	memset(digest->bytes, 0, FIT_SHA1_DIGEST_SIZE);

	uint32_t h[] = {
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476,
		0xC3D2E1F0,
	};
	// Break up message into 512 bit blocks (64 bytes the SHA1_BLOCK_SIZE)

	size_t blockCount = ((messageLen + 8) / 64) + 1;
	uint8_t *messageBlocks = (uint8_t *)calloc(blockCount, FIT_SHA1_BLOCK_SIZE);
	FIT_RELEASE_ASSERT(messageBlocks, "Out of memory when allocating SHA1 block.");

	memcpy(messageBlocks, message, messageLen);

	// Append bit "1" to message (add 0x80)
	messageBlocks[messageLen] = 0x80;

	// implictly appended all the zeros up to the nearest 512 bit block...

	// Append the message length on to teh eng
	uint64_t bitLength = messageLen * 8;

	// convert from little to big endian
	uint64_t bitLengthBigEndian = ((bitLength >> 56) & 0xFF) |
		((bitLength >> 40) & 0xFF00) |
		((bitLength >> 24) & 0xFF0000) |
		((bitLength >> 8) & 0xFF000000) |

		((bitLength << 8) & 0xFF00000000) |
		((bitLength << 24) & 0xFF0000000000) |
		((bitLength << 40) & 0xFF000000000000) |
		((bitLength << 56) & 0xFF00000000000000);

	memcpy(&messageBlocks[(blockCount * FIT_SHA1_BLOCK_SIZE) - sizeof(bitLengthBigEndian)], &bitLengthBigEndian, sizeof(bitLengthBigEndian));

#define FIT_SHA1_ROTL32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

	uint32_t w[80] = {0};

	for (size_t blockIndex = 0; blockIndex < blockCount; blockIndex++) {

		memset(w, 0, sizeof(w));

		// Message schedule : extend the sixteen 32 - bit words into eighty 32 - bit words :
		size_t blockIndexBytes = 64 * blockIndex;
		uint8_t *block = &messageBlocks[blockIndexBytes];

		// Copy the first sixteen 32 bit words of the block
		for (int i = 0; i < 16; ++i) {
			int j = i * 4;
			w[i] = ((uint32_t)block[j] << 24) | ((uint32_t)block[j + 1] << 16) | ((uint32_t)block[j + 2] << 8) | ((uint32_t)block[j + 3]);
		}

		// then extend this to 80 32 bit words
		for (int i = 16; i < 80; ++i) {
			w[i] = FIT_SHA1_ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		}

		//Initialize hash value for this chunk:
		uint32_t a = h[0];
		uint32_t b = h[1];
		uint32_t c = h[2];
		uint32_t d = h[3];
		uint32_t e = h[4];

		for (int i = 0; i < 80; ++i) {
			uint32_t f, k;
			if (i <= 19) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			}
			else if (i >= 20 && i <= 39) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (i >= 40 && i <= 59) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else if (i >= 60 && i <= 79) {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			uint32_t temp = FIT_SHA1_ROTL32(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = FIT_SHA1_ROTL32(b, 30);
			b = a;
			a = temp;
		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
	}

	for (int i = 0; i < 5; ++i) {
		int j = i * 4;
		digest->bytes[j] = (h[i] >> 24) & 0xFF;
		digest->bytes[j + 1] = (h[i] >> 16) & 0xFF;
		digest->bytes[j + 2] = (h[i] >> 8) & 0xFF;
		digest->bytes[j + 3] = h[i] & 0xFF;
	}

	free(messageBlocks);

#undef FIT_SHA1_ROTL32
}

fit_can_abort FIT_Sha1Test() {
	const size_t FIT_MAX_MESSAGE_LENGTH = 1024;
	{
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1("", 0, &digest);
		FIT_Base64Digest base64Digest = {0};
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "2jmj7l5rSw0yVb/vlWAYkK/YBwk=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "The quick brown fox jumps over the lazy dog";
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1(message, strlen(message), &digest);
		FIT_Base64Digest base64Digest;
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "L9ThxnotKPzthJ7hu3bnORuT6xI=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "The quick brown fox jumps over the lazy cog";
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1(message, strlen(message), &digest);
		FIT_Base64Digest base64Digest;
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "3p8sf9JeGzr60+haC9F9mxANtLM=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "dGhlIHNhbXBsZSBub25jZQ==";
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1(message, strlen(message), &digest);
		FIT_Base64Digest base64Digest;
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "hHLtf2V1k8aDQZfNjw3Ia1hCwt0=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1(message, strlen(message), &digest);
		FIT_Base64Digest base64Digest;
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "Kfh9QIsMVZcl6xEPYxPHzW8SZ8w=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		FIT_Sha1Digest digest = {0};
		FIT_DoSha1(message, strlen(message), &digest);
		FIT_Base64Digest base64Digest;
		FIT_DigestToBase64(&digest, &base64Digest);
		FIT_RELEASE_ASSERT(strcmp(base64Digest.buffer, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0, " Sha1 test failed");
	}
}

int FIT_GetAbsolutePath(FIT_Path *path, const char *relativePath) {
	FIT_SHOULD_NOT_BE_NULL(path);
	FIT_SHOULD_NOT_BE_NULL(relativePath);

	char *newPath = _fullpath(path->buffer, relativePath, FIT_MAX_PATH);
	FIT_ASSERT_LOG_RETURN(newPath, "Unable to get an absolute path for relative path [%s]", relativePath);
	path->buffer[FIT_MAX_PATH - 1] = '\0';
	return 1;
}

int FIT_GoUpDirectory(FIT_Path *path, FIT_Path *newPath) {
	FIT_SHOULD_NOT_BE_NULL(path);
	FIT_SHOULD_NOT_BE_NULL(newPath);

	// TODO: this is likely wrong and only works on windows. can work on later

	size_t len = strnlen(path->buffer, FIT_MAX_PATH);
	if (len == 0 || len == 1) return 0;

	size_t index = 0;
	// find last backslash
	for (index = len - 1; index; index--) {
#ifdef _WIN32
		if (path->buffer[index] == '\\') {
			break;
		}
#else 
		if (path->buffer[index] == '/') {
			break;
		}
#endif
	}
	newPath->buffer[0] = '\0';

	for (size_t i = 0; i < index; i++) {
		newPath->buffer[i] = path->buffer[i];
	}

	return 1;
}

int FIT_AppendPath(const FIT_Path *srce, const char *str, FIT_Path *outPath) {
	FIT_SHOULD_NOT_BE_NULL(srce);
	FIT_SHOULD_NOT_BE_NULL(str);
	FIT_SHOULD_NOT_BE_NULL(outPath);

	outPath->buffer[0] = '\0';

	size_t len = strnlen(srce, FIT_MAX_PATH);
	size_t outIndex = 0;
	for (size_t i = 0; i < len; i++) {
		outPath->buffer[outIndex++] = srce->buffer[i];
	}
	FIT_ASSERT_LOG_RETURN(outIndex < FIT_MAX_PATH - 1, "Path size exceeded when attempting to append [%s] to [%s]", str, srce);
#ifdef _WIN32
	outPath->buffer[outIndex++] = '\\';
#else
	outPath.buffer[outIndex++] = '/';
#endif
	len = strnlen(str, FIT_MAX_PATH);
	for (size_t i = 0; i < len; i++) {
		FIT_ASSERT_LOG_RETURN(outIndex < FIT_MAX_PATH, "Path size exceeded when attempting to append [%s] to [%s]", str, srce);
		outPath->buffer[outIndex++] = str[i];
	}
	return 1;
}

void FIT_ContextInit(FIT_Context *ctx) {
	memset(ctx, 0, sizeof(FIT_Context));
}

fit_can_abort FIT_ContextDeinit(FIT_Context *ctx) {
	int result = 0;
	if (ctx->fileStore) {
		result = fclose(ctx->fileStore);
		FIT_RELEASE_ASSERT(result == 0, "Unable to close file");
	}

	for (FIT_FileEntry *entry = ctx->entryHead; entry != NULL;) {
		FIT_FileEntry *next = entry->poolNext;
		free(entry);
		entry = next;
	}
	for (FIT_Snapshot *snap = ctx->snapHead; snap != NULL;) {
		FIT_Snapshot *next = snap->poolNext;
		free(snap);
		snap = next;
	}
}

void *FIT_AddToSnapshotFileEntryList(FIT_Snapshot *snapshot, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(snapshot);
	FIT_SHOULD_NOT_BE_NULL(entry);
	if (snapshot->entryHead == NULL) {
		snapshot->entryHead = entry;
		snapshot->entryTail = entry;
	}
	else {
		snapshot->entryTail->snapNext = entry;
		entry->snapPrev = snapshot->entryTail;
		snapshot->entryTail = entry;
	}
	snapshot->entryCount++;
}

void *FIT_RemoveFromSnapshotFileEntryList(FIT_Snapshot *snapshot, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(snapshot);
	FIT_SHOULD_NOT_BE_NULL(entry);

	if (snapshot->entryHead == entry && snapshot->entryTail == entry) {
		snapshot->entryHead = NULL;
		snapshot->entryTail = NULL;
	}
	else if (snapshot->entryHead == entry) {
		snapshot->entryHead = entry->snapNext;
		snapshot->entryHead->snapPrev = NULL;
	}
	else if (snapshot->entryTail == entry) {
		snapshot->entryTail = entry->snapPrev;
		snapshot->entryTail->snapNext = NULL;
	}
	else {
		entry->snapPrev->snapNext = entry->snapNext;
		entry->snapNext->snapPrev = entry->snapPrev;
	}

	entry->snapNext = NULL;
	entry->snapPrev = NULL;
	snapshot->entryCount--;
}

void *FIT_AddToTrackingList(FIT_Context *ctx, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(entry);

	if (ctx->fsData.entryTrackingHead == NULL) {
		ctx->fsData.entryTrackingHead = entry;
		ctx->fsData.entryTrackingTail = entry;
	}
	else {
		ctx->fsData.entryTrackingTail->trackNext = entry;
		entry->trackPrev = ctx->fsData.entryTrackingTail;
		ctx->fsData.entryTrackingTail = entry;
	}

	ctx->fsData.trackingCount++;
}

void *FIT_RemoveFromTrackList(FIT_Context *ctx, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(entry);

	if (ctx->fsData.entryTrackingHead == entry && ctx->fsData.entryTrackingTail == entry) {
		ctx->fsData.entryTrackingHead = NULL;
		ctx->fsData.entryTrackingTail = NULL;
	}
	else if (ctx->fsData.entryTrackingHead == entry) {
		ctx->fsData.entryTrackingHead = entry->trackNext;
		ctx->fsData.entryTrackingHead->trackPrev = NULL;
	}
	else if (ctx->fsData.entryTrackingTail == entry) {
		ctx->fsData.entryTrackingTail = entry->trackPrev;
		ctx->fsData.entryTrackingTail->trackNext = NULL;
	}
	else {
		entry->trackPrev->trackNext = entry->trackNext;
		entry->trackNext->trackPrev = entry->trackPrev;
	}

	entry->trackNext = NULL;
	entry->trackPrev = NULL;
	ctx->fsData.trackingCount--;
}

void *FIT_AddToSnapshotList(FIT_Context *ctx, FIT_Snapshot *snapshot) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(snapshot);

	if (ctx->fsData.snapshotHead == NULL) {
		ctx->fsData.snapshotHead = snapshot;
		ctx->fsData.snapshotTail = snapshot;
	}
	else {
		ctx->fsData.snapshotTail->next = snapshot;
		snapshot->prev = ctx->fsData.snapshotTail;
		ctx->fsData.snapshotTail = snapshot;
	}
	ctx->fsData.snapshotCount++;
}


void *FIT_RemoveFromSnapshotList(FIT_Context *ctx, FIT_Snapshot *snap) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(snap);

	if (ctx->fsData.snapshotHead == snap && ctx->fsData.snapshotTail == snap) {
		ctx->fsData.snapshotHead = NULL;
		ctx->fsData.snapshotTail = NULL;
	}
	else if (ctx->fsData.snapshotHead == snap) {
		ctx->fsData.snapshotHead = snap->next;
		ctx->fsData.snapshotHead->prev = NULL;
	}
	else if (ctx->fsData.snapshotTail == snap) {
		ctx->fsData.snapshotTail = snap->prev;
		ctx->fsData.snapshotTail->next = NULL;
	}
	else {
		snap->prev->next = snap->next;
		snap->next->prev = snap->prev;
	}

	snap->next = NULL;
	snap->prev = NULL;
	ctx->fsData.snapshotCount--;
}

FIT_Snapshot *FIT_AllocateSnapshot(FIT_Context *ctx) {
	FIT_SHOULD_NOT_BE_NULL(ctx);

	FIT_Snapshot *snapshot = (FIT_Snapshot *)calloc(1, sizeof(FIT_Snapshot));
	FIT_ASSERT_LOG_RETURN(snapshot, "Out of memory, unable to allocate snapshot");
	if (ctx->snapHead == NULL) {
		ctx->snapHead = snapshot;
		ctx->snapTail = snapshot;
	}
	else {
		ctx->snapTail->poolNext = snapshot;
		ctx->snapTail = snapshot;
	}
	return snapshot;
}

FIT_FileEntry *FIT_AllocateFileEntry(FIT_Context *ctx) {
	FIT_SHOULD_NOT_BE_NULL(ctx);

	FIT_FileEntry *entry = (FIT_FileEntry *)calloc(1, sizeof(FIT_FileEntry));
	FIT_ASSERT_LOG_RETURN(entry, "Out of memory, unable to allocate file entry");
	if (ctx->entryHead == NULL) {
		ctx->entryHead = entry;
		ctx->entryTail = entry;
	}
	else {
		ctx->entryTail->poolNext = entry;
		ctx->entryTail = entry;
	}
	return entry;
}

int FIT_IsPathInTrackingList(FIT_Context *ctx, const char *path) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(path);
	for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
		 entry != NULL;
		 entry = entry->trackNext) {
		if (strncmp(entry->path, path, FIT_MAX_PATH) == 0) {
			return 1;
		}
	}
	return 0;
}

int FIT_CopyFileEntry(FIT_FileEntry *dest, FIT_FileEntry *srce) {
	FIT_SHOULD_NOT_BE_NULL(dest);
	FIT_SHOULD_NOT_BE_NULL(srce);

	dest->offset = srce->offset;
	memcpy(dest->hash.buffer, srce->hash.buffer, FIT_BASE64_DIGEST_SIZE);
	dest->path = (char *)calloc(srce->pathLen + 1, sizeof(char));
	FIT_ASSERT_LOG_RETURN(dest->path, "Out of memory in string allocation when copying file entry.");
	strncpy(dest->path, srce->path, srce->pathLen);
	dest->path[srce->pathLen] = '\0';
	dest->pathLen = srce->pathLen;
	dest->offset = srce->offset;
	dest->offsetLen = srce->offsetLen;
}

int FIT_AllocateFileContents(FILE *file, char **buffer, uint64_t *bufferLength) {
	FIT_SHOULD_NOT_BE_NULL(file);
	FIT_SHOULD_NOT_BE_NULL(bufferLength);
	FIT_SHOULD_NOT_BE_NULL(buffer);

	int result = 0;

	result = fseek(file, 0L, SEEK_END);
	FIT_ASSERT_LOG_RETURN(result == 0, "fseek to end of file failed.");

	long fileSize = ftell(file);
	FIT_ASSERT_LOG_RETURN(fileSize != -1L, "ftell failed.");

	fseek(file, 0L, SEEK_SET);
	FIT_ASSERT_LOG_RETURN(result == 0, "fseek to start of file failed.");

	*buffer = NULL;
	if (fileSize == 0) {
		*buffer = (char *)calloc(1, sizeof(char));
		FIT_ASSERT_LOG_RETURN(*buffer, "Unable to allocate memory for file.");
		(*buffer)[0] = '\0';
		*bufferLength = 1;
	}
	else {
		*buffer = (char *)calloc(fileSize, sizeof(char));
		FIT_ASSERT_LOG_RETURN(*buffer, "Unable to allocate memory for file.");
		result = fread(*buffer, fileSize, 1, file);
		FIT_ASSERT_LOG_RETURN(result == 1, "TODO");
		*bufferLength = fileSize;
	}
	return 1;
}

int FIT_HashBuffer(FIT_Base64Digest *base64Digest, char *buffer, uint64_t bufferLen) {
	FIT_SHOULD_NOT_BE_NULL(base64Digest);

	size_t messageLen = bufferLen;

	FIT_Sha1Digest digest = {0};
	FIT_DoSha1(buffer, messageLen, &digest);
	FIT_DigestToBase64(&digest, base64Digest);

	return 1;
}

int FIT_SaveFileEntry(FILE *file, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(file);
	FIT_SHOULD_NOT_BE_NULL(entry);

	int result;

	result = fwrite(&entry->pathLen, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(entry->path, entry->pathLen, 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->hash.buffer, FIT_BASE64_DIGEST_SIZE, 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->offset, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->offsetLen, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	return 1;
}

int FIT_LoadFileEntry(FILE *file, FIT_FileEntry *entry) {
	FIT_SHOULD_NOT_BE_NULL(file);
	FIT_SHOULD_NOT_BE_NULL(entry);

	int result = 0;

	result = fread(&entry->pathLen, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Could not load the path length of a file entry.");
	FIT_ASSERT_LOG_RETURN(entry->pathLen && entry->pathLen < FIT_MAX_PATH, "The path length of a file entry is invalid [%u].", entry->pathLen);

	entry->path = (char *)calloc(entry->pathLen + 1, sizeof(char));
	FIT_ASSERT_LOG_RETURN(entry->path, "Out of memory. Could not allocate string for path of file entry.");

	result = fread(entry->path, entry->pathLen, 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read path of file entry.");
	entry->path[entry->pathLen] = '\0';

	result = fread(&entry->hash.buffer, FIT_BASE64_DIGEST_SIZE, 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read hash of file entry.");
	entry->hash.buffer[FIT_BASE64_DIGEST_SIZE - 1] = '\0';

	result = fread(&entry->offset, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read offset of file entry.");

	result = fread(&entry->offsetLen, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read offset length of file entry.");

	return 1;
}

int FIT_SaveFileStoreFromBuffer(FIT_Context *ctx, FILE *file) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(file);

	static uint32_t version = 0;
	int result = 0;

	result = fwrite(&version, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&ctx->fsData.snapshotCount, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	for (FIT_Snapshot *snapshot = ctx->fsData.snapshotHead;
		 snapshot != NULL;
		 snapshot = snapshot->next) {

		uint32_t entryListCount = snapshot->entryCount;
		result = fwrite(&entryListCount, sizeof(uint32_t), 1, file);
		FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

		for (FIT_FileEntry *entry = snapshot->entryHead;
			 entry != NULL;
			 entry = entry->snapNext) {
			result = FIT_SaveFileEntry(file, entry);
			FIT_ASSERT_LOG_RETURN(result == 1, "TODO");
		}
	}

	result = fwrite(&ctx->fsData.trackingCount, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
		 entry != NULL;
		 entry = entry->trackNext) {
		result = FIT_SaveFileEntry(file, entry);
		FIT_ASSERT_LOG_RETURN(result == 1, "TODO");
	}

	result = fwrite(&ctx->fsData.bufferCount, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

	if (ctx->fsData.bufferCount) {
		result = fwrite(ctx->fsData.buffer, ctx->fsData.bufferCount, 1, file);
		FIT_ASSERT_LOG_RETURN(result == 1, "TODO");
	}

	return 1;
}

int FIT_SaveFileStoreFromFile(FIT_Context *ctx, const char *path) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(path);

	int result = 0;

	FIT_RELEASE_ASSERT(ctx->fileStore == NULL, "Trying to save the file store after it's already been opened");

	ctx->fileStore = fopen(path, "wb");
	FIT_ASSERT_LOG_RETURN(ctx->fileStore, "Unable to open file [%s]", path);

	result = FIT_SaveFileStoreFromBuffer(ctx, ctx->fileStore);
	FIT_ASSERT_LOG_RETURN(result, "TODO");

	result = fclose(ctx->fileStore);
	FIT_ASSERT_LOG_RETURN(result == 0, "TODO");

	ctx->fileStore = NULL;

	return 1;
}

int FIT_LoadFileStoreFromBuffer(FIT_Context *ctx, FILE *file) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(file);

	uint32_t version = 0;
	int result = 0;

	result = fread(&version, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to load version to file store");
	FIT_ASSERT_LOG_RETURN(version == 0, "Only version 0 supported.");

	uint32_t snapshotCount;
	result = fread(&snapshotCount, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to load snapshot count to file store");

	for (uint32_t isnap = 0; isnap < snapshotCount; isnap++) {

		FIT_Snapshot *snapshot = FIT_AllocateSnapshot(ctx);
		FIT_ASSERT_LOG_RETURN(snapshot, "Unable to use snapshot");

		FIT_AddToSnapshotList(ctx, snapshot);

		uint32_t entryListCount = 0;
		result = fread(&entryListCount, sizeof(uint32_t), 1, file);
		FIT_ASSERT_LOG_RETURN(result == 1, "Unable to load file entry list count from file store");

		for (uint32_t ientry = 0; ientry < entryListCount; ientry++) {

			FIT_FileEntry *entry = FIT_AllocateFileEntry(ctx);
			FIT_ASSERT_LOG_RETURN(entry, "Unable to use file entry");

			entry->inSnapshot = 1;

			FIT_AddToSnapshotFileEntryList(snapshot, entry);

			result = FIT_LoadFileEntry(file, entry);
			FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read file entry.");
		}
	}

	uint32_t trackingListCount;
	result = fread(&trackingListCount, sizeof(uint32_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read tracking list count.");

	int index = 0;
	for (uint32_t ientry = 0; ientry < trackingListCount; ientry++) {

		FIT_FileEntry *entry = FIT_AllocateFileEntry(ctx);
		FIT_ASSERT_LOG_RETURN(entry, "Unable to allocate file entry");

		FIT_AddToTrackingList(ctx, entry);

		result = FIT_LoadFileEntry(file, entry);
		FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read tracking file entry [%d]. It is recommended to clear the tracking list and try again.", index);
		index++;
	}

	result = fread(&ctx->fsData.bufferCount, sizeof(uint64_t), 1, file);
	FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read the buffer count of the file store.");
	FIT_ASSERT_LOG_RETURN(ctx->fsData.bufferCount < 100000, "Buffer count of file store is invalid.");

	if (ctx->fsData.bufferCount) {
		ctx->fsData.buffer = (char *)calloc(ctx->fsData.bufferCount, sizeof(char));
		FIT_ASSERT_LOG_RETURN(ctx->fsData.buffer, "Out of memory. Unable allocate memory for buffer when loading file store.");

		result = fread(ctx->fsData.buffer, ctx->fsData.bufferCount, 1, file);
		FIT_ASSERT_LOG_RETURN(result == 1, "Unable to read buffer memory of file store.");
	}

	return 1;
}

int FIT_LoadFileStoreFromFile(FIT_Context *ctx, const char *filename) {
	FIT_SHOULD_NOT_BE_NULL(ctx);
	FIT_SHOULD_NOT_BE_NULL(filename);

	FIT_RELEASE_ASSERT(ctx->fileStore == NULL, "Trying to load the file store after it's already been loaded");

	ctx->fileStore = fopen(filename, "rb");
	FIT_ASSERT_LOG_RETURN(ctx->fileStore, "Unable to open file [%s]", filename);

	int result = FIT_LoadFileStoreFromBuffer(ctx, ctx->fileStore);
	FIT_ASSERT_LOG_RETURN(result, "Unable to load file store from buffer");

	result = fclose(ctx->fileStore);
	FIT_ASSERT_LOG_RETURN(result == 0, "TODO");

	ctx->fileStore = NULL;

	return 1;
}

int FIT_Run(FIT_Context *ctx, int argc, char *argv[]) {
	FIT_SHOULD_NOT_BE_NULL(ctx);

	FIT_Sha1Test();

	if (argc <= 1) {
		FIT_LOG(
			"The FileStore is a program which takes a set of user supplied files\n"
			"and tracks and stores snapshots of these files within an FileStore file [.fs].\n"
			"Common usage:\n"
			"\"fs create <file store name>\" // creates a file store that you can store files in.\n"
			"\"fs add <file store name> <file to add>\" // adds a file to the file store\n"
		);
		return 1;
	}

	const char *commandStr = argv[1];
	FIT_ASSERT_LOG_RETURN(commandStr, "Error. The second argument is a NULL.");

	// Work out what the command is.
	const size_t MAX_COMMAND_LENGTH = 32;

	size_t commandLen = strnlen(commandStr, MAX_COMMAND_LENGTH);

	typedef enum FIT_COMMAND {
		FIT_CREATE = 0,
		FIT_SAVE,
		FIT_TRACK,
		FIT_TRACK_ALL,
		FIT_TRACK_LIST,
		FIT_UNTRACK,
		FIT_SNAPS,
		FIT_LOAD,


		FIT_COMMAND_COUNT
	} FIT_COMMAND;

	FIT_COMMAND command = FIT_COMMAND_COUNT;

	if (strncmp("create", commandStr, commandLen) == 0) {
		command = FIT_CREATE;
	}
	else if (strncmp("save", commandStr, commandLen) == 0) {
		command = FIT_SAVE;
	}
	else if (strncmp("track", commandStr, commandLen) == 0) {
		command = FIT_TRACK;
	}
	else if (strncmp("track_all", commandStr, commandLen) == 0) {
		command = FIT_TRACK;
	}
	else if (strncmp("tracklist", commandStr, commandLen) == 0) {
		command = FIT_TRACK_LIST;
	}
	else if (strncmp("untrack", commandStr, commandLen) == 0) {
		command = FIT_UNTRACK;
	}
	else if (strncmp("snaps", commandStr, commandLen) == 0) {
		command = FIT_SNAPS;
	}
	else if (strncmp("load", commandStr, commandLen) == 0) {
		command = FIT_LOAD;
	}
	else {
		FIT_LOG("This command [%s] is unrecognised. Try \"fv <cheat>\" to a see a list of useful commands, or \"fv <help>\" for some help.", commandStr);
		return 0;
	}

	switch (command) {
	case FIT_CREATE: {
		if (argc >= 2) {
			const char *fileName = argv[2];
			FIT_ASSERT_LOG_RETURN(fileName, "Error. The third argument is a NULL.");

			// We need to append the .fv suffix;
			char path[FIT_MAX_PATH] = {0};

			strncpy(path, fileName, FIT_MAX_PATH - 1);
			path[FIT_MAX_PATH - 1] = '\0';
			strncat(path, ".fit", FIT_MAX_PATH - 1);

			// Check the file exists 
			FILE *file = fopen(path, "rb");
			FIT_ASSERT_LOG_RETURN(!file, "The file [%s] already exists. So no file was created.", path);

			int result = FIT_SaveFileStoreFromFile(ctx, path);
			FIT_ASSERT_LOG_RETURN(result, "TODO");

			FIT_LOG("Sucessfully created the %s file store.", path);
		}
		break;
	}
	case FIT_TRACK_LIST: {

		if (argc >= 2) {

			int result;
			{
				const char *fileStoreStr = argv[2];
				FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

				// Extract the full path of the file store
				result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
				FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
			}

			result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
			FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

			result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
			FIT_ASSERT_LOG_RETURN(result, "Unable to load the file store [%s]. Does this file exist?", ctx->fileStoreAbsolutePath.buffer);

			FIT_LOG(" ");

			int index = 0;
			for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
				 entry != NULL;
				 entry = entry->trackNext) {

				FIT_LOG("[%d] %s [%s]", index++, entry->path, entry->hash.buffer);
			}

			FIT_LOG(" ");
		}

		break;
	}
	case FIT_UNTRACK: {

		if (argc >= 3) {

			int result;
			{
				const char *fileStoreStr = argv[2];
				FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

				// Extract the full path of the file store
				result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
				FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
			}

			result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
			FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

			result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
			FIT_ASSERT_LOG_RETURN(result, "Unable to load the file store [%s]. Does this file exist?", ctx->fileStoreAbsolutePath.buffer);

			const char *fileTrackStr = argv[3];
			FIT_ASSERT_LOG_RETURN(fileTrackStr, "The <fileToTrack> argument is a NULL.");

			FIT_FileEntry *entryToRemove = NULL;
			for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
				 entry != NULL;
				 entry = entry->trackNext) {
				if (strncmp(entry->path, fileTrackStr, entry->pathLen) == 0) {
					entryToRemove = entry;
					break;
				}
			}

			if (entryToRemove) {
				FIT_LOG("\nRemoving [%s] from the tracking list.\n", entryToRemove->path);

				FIT_RemoveFromTrackList(ctx, entryToRemove);
				result = FIT_SaveFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
				FIT_ASSERT_LOG_RETURN(result, "TODO");
			}
			else {
				FIT_LOG("\nThis file [%s] is not being tracked and is not in the tracking list.\n", fileTrackStr);
			}
		}

		break;
	}
	case FIT_SAVE: {

		if (argc >= 2) {

			int result;
			{
				const char *fileStoreStr = argv[2];
				FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

				// Extract the full path of the file store
				result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
				FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
			}

			result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
			FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

			result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
			FIT_ASSERT_LOG_RETURN(result, "Unable to load the file store [%s].", ctx->fileStoreAbsolutePath.buffer);

			int newChanges = 0;

			FIT_LOG(" ");

			if (ctx->fsData.trackingCount) {

				FIT_Snapshot *snapshot = FIT_AllocateSnapshot(ctx);

				if (ctx->fsData.snapshotCount == 0) {

					for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
						 entry != NULL;
						 entry = entry->trackNext) {

						FIT_LOG(" - A new file [*%s] has been added to the store.", entry->path);
						newChanges++;
						FIT_AddToSnapshotFileEntryList(snapshot, entry);
					}
				}
				else {

					FIT_Snapshot *lastSnapshot = ctx->fsData.snapshotTail;

					for (FIT_FileEntry *entry = ctx->fsData.entryTrackingHead;
						 entry != NULL;
						 entry = entry->trackNext) {

						// is it in the last snapshot list 
						int isInSnapList = 0;
						for (FIT_FileEntry *snapEntry = lastSnapshot->entryHead;
							 snapEntry != NULL;
							 snapEntry = snapEntry->snapNext) {

							if (strncmp(entry->path, snapEntry->path, FIT_MAX_PATH) == 0) {
								isInSnapList = 1;
								break;
							}
						}
						if (!isInSnapList) {
							FIT_LOG(" - A new file [*%s] has been added to the store.", entry->path);
							newChanges++;
						}

						FIT_AddToSnapshotFileEntryList(snapshot, entry);
					}
				}

				for (FIT_FileEntry *entry = snapshot->entryHead; entry != NULL;) {
					FIT_FileEntry *entryNext = entry->snapNext;

					result = FIT_AppendPath(&ctx->workingDirectory, entry->path, &ctx->trackedFileAbsolutePath);
					FIT_ASSERT_LOG_RETURN(result, "Unable to append entry relative path to working directory path.");

					FILE *file = fopen(ctx->trackedFileAbsolutePath.buffer, "rb");
					if (!file) { // If we cannot open the file, then we assume the change is that this file has been deleted.

						FIT_LOG(" - It appears that file [%s] has been renamed or deleted since the last snapshot.", entry->path);
						newChanges++;
						// remove entry from the current snapshot and track list
						FIT_RemoveFromSnapshotFileEntryList(snapshot, entry);
						FIT_RemoveFromTrackList(ctx, entry);
					}
					else {

						result = FIT_AllocateFileContents(file, &entry->buffer, &entry->bufferLen);
						FIT_ASSERT_LOG_RETURN(result, "TODO");

						if (entry->inSnapshot) {
							FIT_Base64Digest digest = {0};
							result = FIT_HashBuffer(&digest, entry->buffer, entry->bufferLen);
							FIT_ASSERT_LOG_RETURN(result, "TODO");

							// if the hash changes then we need to save the new buffer
							if (strncmp(digest.buffer, entry->hash.buffer, FIT_MAX_PATH) != 0) {

								memcpy(entry->hash.buffer, digest.buffer, FIT_BASE64_DIGEST_SIZE);

								entry->offset = ctx->fsData.bufferCount;
								ctx->fsData.bufferCount += entry->bufferLen;
								entry->offsetLen = entry->bufferLen;

								char *newBuffer = realloc(ctx->fsData.buffer, ctx->fsData.bufferCount);
								FIT_ASSERT_LOG_RETURN(newBuffer, "TODO");
								ctx->fsData.buffer = newBuffer;
								memcpy(&ctx->fsData.buffer[entry->offset], entry->buffer, entry->offsetLen);

								FIT_LOG(" - A file [*%s] has changed since the last snapshot. It's new contents will be added to the store.", entry->path);
								newChanges++;
							}
						}
						else {
							result = FIT_HashBuffer(&entry->hash, entry->buffer, entry->bufferLen);
							FIT_ASSERT_LOG_RETURN(result, "TODO");

							entry->offset = ctx->fsData.bufferCount;
							ctx->fsData.bufferCount += entry->bufferLen;
							entry->offsetLen = entry->bufferLen;

							char *newBuffer = realloc(ctx->fsData.buffer, ctx->fsData.bufferCount);
							FIT_ASSERT_LOG_RETURN(newBuffer, "TODO");
							ctx->fsData.buffer = newBuffer;
							memcpy(&ctx->fsData.buffer[entry->offset], entry->buffer, entry->offsetLen);
						}
					}

					entry = entryNext;
				}

				FIT_AddToSnapshotList(ctx, snapshot);

				result = FIT_SaveFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
				FIT_ASSERT_LOG_RETURN(result, "TODO");

				FIT_LOG(" ");

				if (!newChanges) {
					FIT_LOG("No files have changes since the last snapshot.");
				}

				FIT_LOG("Saved snapshot [%d] to the file store.\n", ctx->fsData.snapshotCount - 1);

			}
			else {
				FIT_LOG("There are no currently tracked files that can be saved into this file store [%s]\n", ctx->fileStoreAbsolutePath.buffer);
			}
		}
		break;
	}
	case FIT_TRACK: {

		if (argc >= 3) {

			int result = 0;
			{
				const char *fileStoreStr = argv[2];
				FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

				// Extract the full path of the file store
				result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
				FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
			}

			result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
			FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

			const char *fileTrackStr = argv[3];
			FIT_ASSERT_LOG_RETURN(fileTrackStr, "The <fileToTrack> argument is a NULL.");

			result = FIT_AppendPath(&ctx->workingDirectory, fileTrackStr, &ctx->trackedFileAbsolutePath);
			FIT_ASSERT_LOG_RETURN(result, "Unable to append track filename to working directory path.");

			result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
			FIT_ASSERT_LOG_RETURN(result, "The store [%s] could not be opened. Does it exist?", ctx->fileStoreAbsolutePath.buffer);

			FILE *fileToTrack = fopen(ctx->trackedFileAbsolutePath.buffer, "rb");
			FIT_ASSERT_LOG_RETURN(fileToTrack, "Unable to open the [%s] file to track.", ctx->trackedFileAbsolutePath.buffer);

			// Check that the file is not already in the tracking list 
			if (FIT_IsPathInTrackingList(ctx, fileTrackStr)) {
				FIT_LOG("This file [%s] is already being tracked. Only one instance of a file can be tracked at a time.", fileTrackStr);
			}
			else {

				FIT_FileEntry *entry = FIT_AllocateFileEntry(ctx);
				FIT_ASSERT_LOG_RETURN(entry, "TODO");

				size_t strLen = strnlen(fileTrackStr, FIT_MAX_PATH);
				FIT_ASSERT_LOG_RETURN(strLen, "The path length of the specified tracked file is 0. This is an error.");

				char *str = (char *)calloc(strLen + 1, sizeof(char));
				FIT_ASSERT_LOG_RETURN(str, "Out of memory. Unable to allocate string.");
				strncpy(str, fileTrackStr, strLen);
				str[strLen] = '\0';

				entry->path = str;
				entry->pathLen = strLen;

				FIT_AddToTrackingList(ctx, entry);

				result = FIT_SaveFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
				FIT_ASSERT_LOG_RETURN(result, "TODO");

				FIT_LOG("The file [%s] is now being tracked by the store [%s]", entry->path, ctx->fileStoreAbsolutePath.buffer);
			}
		}
		break;
	}
	case FIT_TRACK_ALL: {

		//if (argc >= 3) {

		//	int result = 0;
		//	{
		//		const char *fileStoreStr = argv[2];
		//		FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

		//		// Extract the full path of the file store
		//		result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
		//		FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
		//	}

		//	result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
		//	FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

		//	const char *fileTrackStr = argv[3];
		//	FIT_ASSERT_LOG_RETURN(fileTrackStr, "The <fileToTrack> argument is a NULL.");

		//	result = FIT_AppendPath(&ctx->workingDirectory, fileTrackStr, &ctx->trackedFileAbsolutePath);
		//	FIT_ASSERT_LOG_RETURN(result, "Unable to append track filename to working directory path.");

		//	result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
		//	FIT_ASSERT_LOG_RETURN(result, "The store [%s] could not be opened. Does it exist?", ctx->fileStoreAbsolutePath.buffer);

		//	FILE *fileToTrack = fopen(ctx->trackedFileAbsolutePath.buffer, "rb");
		//	FIT_ASSERT_LOG_RETURN(fileToTrack, "Unable to open the [%s] file to track.", ctx->trackedFileAbsolutePath.buffer);

		//	// Check that the file is not already in the tracking list 
		//	if (FIT_IsPathInTrackingList(ctx, fileTrackStr)) {
		//		FIT_LOG("This file [%s] is already being tracked. Only one instance of a file can be tracked at a time.", fileTrackStr);
		//	}
		//	else {

		//		FIT_FileEntry *entry = FIT_AllocateFileEntry(ctx);
		//		FIT_ASSERT_LOG_RETURN(entry, "TODO");

		//		size_t strLen = strnlen(fileTrackStr, FIT_MAX_PATH);
		//		FIT_ASSERT_LOG_RETURN(strLen, "The path length of the specified tracked file is 0. This is an error.");

		//		char *str = (char *)calloc(strLen + 1, sizeof(char));
		//		FIT_ASSERT_LOG_RETURN(str, "Out of memory. Unable to allocate string.");
		//		strncpy(str, fileTrackStr, strLen);
		//		str[strLen] = '\0';

		//		entry->path = str;
		//		entry->pathLen = strLen;

		//		FIT_AddToTrackingList(ctx, entry);

		//		result = FIT_SaveFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
		//		FIT_ASSERT_LOG_RETURN(result, "TODO");

		//		FIT_LOG("The file [%s] is now being tracked by the store [%s]", entry->path, ctx->fileStoreAbsolutePath.buffer);
		//	}
		//}
		break;
	}
	case FIT_LOAD: {

		if (argc >= 3) {

			int result = 0;
			{
				const char *fileStoreStr = argv[2];
				FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

				// Extract the full path of the file store
				result = FIT_GetAbsolutePath(&ctx->fileStoreAbsolutePath, fileStoreStr);
				FIT_ASSERT_LOG_RETURN(result, "Unable to get the absolute path for the file store.");
			}

			result = FIT_GoUpDirectory(&ctx->fileStoreAbsolutePath, &ctx->workingDirectory);
			FIT_ASSERT_LOG_RETURN(result, "Unable to get the working directory for the file store.");

			result = FIT_LoadFileStoreFromFile(ctx, ctx->fileStoreAbsolutePath.buffer);
			FIT_ASSERT_LOG_RETURN(result, "TODO");

			FIT_Snapshot *snapshot = NULL;
			long int snapIndex = 0;

			if (argc >= 4) {
				const char *snapIndexStr = argv[3];
				FIT_ASSERT_LOG_RETURN(snapIndexStr, "The <snapIndex> argument is a NULL.");

				snapIndex = strtol(snapIndexStr, NULL, 0);

				long int curIndex = 0;
				// this is slow
				for (FIT_Snapshot *s = ctx->fsData.snapshotHead;
					 s != NULL;
					 s = s->next) {
					if (curIndex++ == snapIndex) {
						snapshot = s;
						break;
					}
				}
				FIT_ASSERT_LOG_RETURN(snapshot, "The provided snapshot index does not reference any snapshot in the store. Omitting the index will load the latest snapshot.");
			}
			else {
				snapshot = ctx->fsData.snapshotTail;
			}

			for (FIT_FileEntry *entry = snapshot->entryHead;
				 entry != NULL;
				 entry = entry->snapNext) {

				result = FIT_AppendPath(&ctx->workingDirectory, entry->path, &ctx->trackedFileAbsolutePath);
				FIT_ASSERT_LOG_RETURN(result, "Unable to append entry relative path to working directory path.");

				FILE *file = fopen(ctx->trackedFileAbsolutePath.buffer, "wb");
				FIT_ASSERT_LOG_RETURN(file, "TODO");

				int result = fwrite(&ctx->fsData.buffer[entry->offset], entry->offsetLen, 1, file);
				FIT_ASSERT_LOG_RETURN(result == 1, "TODO");

				result = fclose(file);
				FIT_ASSERT_LOG_RETURN(result == 0, "TODO");
			}

			if (snapshot == ctx->fsData.snapshotTail) {
				FIT_Log("Successfully loaded the latest snapshot");
			}
			else {
				FIT_Log("Successfully loaded snapshot %d", snapIndex);
			}

		}

		break;
	}
	case FIT_SNAPS: {

		if (argc >= 3) {
			const char *fileStoreStr = argv[2];
			FIT_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

			int result = FIT_LoadFileStoreFromFile(ctx, fileStoreStr);
			FIT_ASSERT_LOG_RETURN(result, "TODO");

			if (ctx->fsData.snapshotCount) {

				FIT_LOG(" ");

				int index = 0;
				for (FIT_Snapshot *snap = ctx->fsData.snapshotHead;
					 snap != NULL;
					 snap = snap->next) {

					if (index == ctx->fsData.snapshotCount - 1) {
						FIT_LOG("------ %s | Snapshot [%d] [LATEST] ------\n", fileStoreStr, index++);
					}
					else {
						FIT_LOG("------ %s | Snapshot [%d] ------\n", fileStoreStr, index++);
					}

					for (FIT_FileEntry *entry = snap->entryHead;
						 entry != NULL;
						 entry = entry->snapNext) {
						FIT_LOG(" - [%s] [%s]", entry->path, entry->hash.buffer);
					}

					FIT_LOG(" ");
				}

			}
			else {
				FIT_LOG("There are no saved snap shots to look at.");
			}
		}
		break;
	}
	}

	return 1;
}
#endif

#endif
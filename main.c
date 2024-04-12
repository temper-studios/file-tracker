#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>

typedef void fs_can_abort;

#define FS_MAX_PATH 256

void FS_Log(const char *format, ...) {
	va_list args = {0};
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	fprintf(stdout, "\n");
}

void FS_AbortWithMessage(const char *format, ...) {
	va_list args = {0};
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	exit(0);
}

#define FS_RELEASE_ASSERT(condition, format, ...) if (!(condition)) FS_AbortWithMessage(format, __VA_ARGS__)
#define FS_DEBUG_ASSERT(condition, format, ...) assert(condition)
#define FS_SHOULD_NOT_BE_NULL(condition) FS_DEBUG_ASSERT(condition, "")
#define FS_ABORT_WITH_MESSAGE(format, ...) FS_AbortWithMessage(format, __VA_ARGS__)
#define FS_ASSERT_LOG_RETURN(condition, format, ...) if (!(condition)) { FS_Log(format, __VA_ARGS__); return 0; }
#define FS_LOG(format, ...) FS_Log(format, __VA_ARGS__)

// SHA-1 constants
#define FS_SHA1_BLOCK_SIZE 64
// this is an 160 bit number
#define FS_SHA1_DIGEST_SIZE 20
// 20 bytes (160 bits) => 28 characters in Base64
#define FS_BASE64_DIGEST_SIZE 64
#define FS_BASE64_OUTPUT_STR_SIZE (4 * ((FS_SHA1_DIGEST_SIZE + 2) / 3)) 

// Base64 encoding lookup table
static const char FS_BASE64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct FS_Sha1Digest {
	uint8_t bytes[FS_SHA1_DIGEST_SIZE];
} FS_Sha1Digest;

typedef struct FS_Base64Digest {
	char buffer[FS_BASE64_DIGEST_SIZE];
} FS_Base64Digest;

void FS_DigestToBase64(FS_Sha1Digest *input, FS_Base64Digest *output) {
	FS_SHOULD_NOT_BE_NULL(input);
	FS_SHOULD_NOT_BE_NULL(output);

	size_t input_len = FS_SHA1_DIGEST_SIZE;
	size_t output_len = FS_BASE64_OUTPUT_STR_SIZE;

	FS_DEBUG_ASSERT(output_len < FS_BASE64_DIGEST_SIZE);

	for (size_t i = 0, j = 0; i < input_len;) {
		uint32_t octet_a = (i < input_len) ? input->bytes[i++] : 0;
		uint32_t octet_b = (i < input_len) ? input->bytes[i++] : 0;
		uint32_t octet_c = (i < input_len) ? input->bytes[i++] : 0;

		uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

		output->buffer[j++] = FS_BASE64_TABLE[(triple >> 18) & 0x3F];
		output->buffer[j++] = FS_BASE64_TABLE[(triple >> 12) & 0x3F];
		output->buffer[j++] = FS_BASE64_TABLE[(triple >> 6) & 0x3F];
		output->buffer[j++] = FS_BASE64_TABLE[triple & 0x3F];
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

void FS_DoSha1(const char *message, size_t messageLen, FS_Sha1Digest *digest) {
	FS_SHOULD_NOT_BE_NULL(message);
	FS_SHOULD_NOT_BE_NULL(digest);

	memset(digest->bytes, 0, FS_SHA1_DIGEST_SIZE);

	uint32_t h[] = {
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476,
		0xC3D2E1F0,
	};
	// Break up message into 512 bit blocks (64 bytes the SHA1_BLOCK_SIZE)

	size_t blockCount = ((messageLen + 8) / 64) + 1;
	uint8_t *messageBlocks = (uint8_t *)calloc(blockCount, FS_SHA1_BLOCK_SIZE);
	FS_RELEASE_ASSERT(messageBlocks, "Out of memory when allocating SHA1 block.");

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

	memcpy(&messageBlocks[(blockCount * FS_SHA1_BLOCK_SIZE) - sizeof(bitLengthBigEndian)], &bitLengthBigEndian, sizeof(bitLengthBigEndian));

#define FS_SHA1_ROTL32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

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
			w[i] = FS_SHA1_ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
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

			uint32_t temp = FS_SHA1_ROTL32(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = FS_SHA1_ROTL32(b, 30);
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

#undef FS_SHA1_ROTL32
}

fs_can_abort FS_Sha1Test() {
	const size_t FS_MAX_MESSAGE_LENGTH = 1024;
	{
		FS_Sha1Digest digest = {0};
		FS_DoSha1("", 0, &digest);
		FS_Base64Digest base64Digest = {0};
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "2jmj7l5rSw0yVb/vlWAYkK/YBwk=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "The quick brown fox jumps over the lazy dog";
		FS_Sha1Digest digest = {0};
		FS_DoSha1(message, strlen(message), &digest);
		FS_Base64Digest base64Digest;
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "L9ThxnotKPzthJ7hu3bnORuT6xI=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "The quick brown fox jumps over the lazy cog";
		FS_Sha1Digest digest = {0};
		FS_DoSha1(message, strlen(message), &digest);
		FS_Base64Digest base64Digest;
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "3p8sf9JeGzr60+haC9F9mxANtLM=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "dGhlIHNhbXBsZSBub25jZQ==";
		FS_Sha1Digest digest = {0};
		FS_DoSha1(message, strlen(message), &digest);
		FS_Base64Digest base64Digest;
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "hHLtf2V1k8aDQZfNjw3Ia1hCwt0=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		FS_Sha1Digest digest = {0};
		FS_DoSha1(message, strlen(message), &digest);
		FS_Base64Digest base64Digest;
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "Kfh9QIsMVZcl6xEPYxPHzW8SZ8w=") == 0, " Sha1 test failed");
	}
	{
		const char message[] = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		FS_Sha1Digest digest = {0};
		FS_DoSha1(message, strlen(message), &digest);
		FS_Base64Digest base64Digest;
		FS_DigestToBase64(&digest, &base64Digest);
		FS_RELEASE_ASSERT(strcmp(base64Digest.buffer, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0, " Sha1 test failed");
	}
}

typedef struct FS_FileEntry {
	char *path;
	uint32_t pathLen;
	FS_Base64Digest hash;
	uint64_t offset;
	uint64_t offsetLen;
	char *buffer;
	uint64_t bufferLen;
	int inSnapshot;

	struct FS_FileEntry *poolNext;
	struct FS_FileEntry *snapNext;
	struct FS_FileEntry *snapPrev;
	struct FS_FileEntry *trackNext;
	struct FS_FileEntry *trackPrev;
} FS_FileEntry;

typedef struct FS_Snapshot {
	FS_FileEntry *entryHead;
	FS_FileEntry *entryTail;
	uint32_t entryCount;
	struct FS_Snapshot *next;
	struct FS_Snapshot *prev;
	struct FS_Snapshot *poolNext;
} FS_Snapshot;

typedef struct FS_FileStoreData {
	FS_Snapshot *snapshotHead;
	FS_Snapshot *snapshotTail;
	FS_FileEntry *entryTrackingHead;
	FS_FileEntry *entryTrackingTail;
	char *buffer;
	uint64_t bufferCount;
	uint32_t snapshotCount;
	uint32_t trackingCount;
} FS_FileStoreData;

typedef struct FS_State {
	FS_FileStoreData fsData;
	uint64_t offset;
	FS_FileEntry *entryHead;
	FS_FileEntry *entryTail;
	FS_Snapshot *snapHead;
	FS_Snapshot *snapTail;
} FS_State;

static FS_State fs_State;

void *FS_AddToSnapshotFileEntryList(FS_Snapshot *snapshot, FS_FileEntry *entry) {
	FS_SHOULD_NOT_BE_NULL(snapshot);
	FS_SHOULD_NOT_BE_NULL(entry);
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

void *FS_AddToTrackingList(FS_FileEntry *entry) {
	FS_SHOULD_NOT_BE_NULL(entry);

	if (fs_State.fsData.entryTrackingHead == NULL) {
		fs_State.fsData.entryTrackingHead = entry;
		fs_State.fsData.entryTrackingTail = entry;
	}
	else {
		fs_State.fsData.entryTrackingHead->trackNext = entry;
		entry->trackPrev = fs_State.fsData.entryTrackingTail;
		fs_State.fsData.entryTrackingTail = entry;
	}

	fs_State.fsData.trackingCount++;
}

void *FS_AddToSnapshotList(FS_Snapshot *snapshot) {
	FS_SHOULD_NOT_BE_NULL(snapshot);

	if (fs_State.fsData.snapshotHead == NULL) {
		fs_State.fsData.snapshotHead = snapshot;
		fs_State.fsData.snapshotTail = snapshot;
	}
	else {
		fs_State.fsData.snapshotTail->next = snapshot;
		snapshot->prev = fs_State.fsData.snapshotTail;
		fs_State.fsData.snapshotTail = snapshot;
	}
	fs_State.fsData.snapshotCount++;
}

FS_Snapshot *FS_AllocateSnapshot() {
	FS_Snapshot *snapshot = (FS_Snapshot *)calloc(1, sizeof(FS_Snapshot));
	FS_ASSERT_LOG_RETURN(snapshot, "Out of memory, unable to allocate snapshot");
	if (fs_State.snapHead == NULL) {
		fs_State.snapHead = snapshot;
		fs_State.snapTail = snapshot;
	}
	else {
		fs_State.snapTail->poolNext = snapshot;
		fs_State.snapTail = snapshot;
	}
	return snapshot;
}

FS_FileEntry *FS_AllocateFileEntry() {
	FS_FileEntry *entry = (FS_FileEntry *)calloc(1, sizeof(FS_FileEntry));
	FS_ASSERT_LOG_RETURN(entry, "Out of memory, unable to allocate file entry");
	if (fs_State.entryHead == NULL) {
		fs_State.entryHead = entry;
		fs_State.entryTail = entry;
	}
	else {
		fs_State.entryTail->poolNext = entry;
		fs_State.entryTail = entry;
	}
	return entry;
}

int FS_AllocateFileContents(FILE *file, char **buffer, uint64_t *bufferLength) {
	FS_SHOULD_NOT_BE_NULL(file);
	FS_SHOULD_NOT_BE_NULL(bufferLength);
	FS_SHOULD_NOT_BE_NULL(buffer);

	int result = 0;

	result = fseek(file, 0L, SEEK_END);
	FS_ASSERT_LOG_RETURN(result == 0, "fseek to end of file failed.");

	long fileSize = ftell(file);
	FS_ASSERT_LOG_RETURN(fileSize != -1L, "ftell failed.");

	fseek(file, 0L, SEEK_SET);
	FS_ASSERT_LOG_RETURN(result == 0, "fseek to start of file failed.");
	
	*buffer = NULL;
	if (fileSize == 0) {
		*buffer = (char *)calloc(1, sizeof(char));
		FS_ASSERT_LOG_RETURN(*buffer, "Unable to allocate memory for file.");
		(*buffer)[0] = '\0';
		*bufferLength = 1;
	}
	else {
		*buffer = (char *)calloc(fileSize, sizeof(char));
		FS_ASSERT_LOG_RETURN(*buffer, "Unable to allocate memory for file.");
		result = fread(*buffer, fileSize, 1, file);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");
		*bufferLength = fileSize;
	}
	return 1;
}

int FS_HashBuffer(FS_Base64Digest *base64Digest, char *buffer, uint64_t bufferLen) {
	FS_SHOULD_NOT_BE_NULL(base64Digest);

	size_t messageLen = bufferLen;

	FS_Sha1Digest digest = {0};
	FS_DoSha1(buffer, messageLen, &digest);
	FS_DigestToBase64(&digest, base64Digest);

	return 1;
}

int FS_SaveFileEntry(FILE *file, FS_FileEntry *entry) {
	FS_SHOULD_NOT_BE_NULL(entry);

	int result;

	result = fwrite(&entry->pathLen, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	result = fwrite(entry->path, entry->pathLen, 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->hash.buffer, FS_BASE64_DIGEST_SIZE, 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->offset, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&entry->offsetLen, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	return 1;
}

int FS_LoadFileEntry(FILE *file, FS_FileEntry *entry) {
	FS_SHOULD_NOT_BE_NULL(entry);
	int result = 0;

	result = fread(&entry->pathLen, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	FS_ASSERT_LOG_RETURN(entry->pathLen && entry->pathLen < FS_MAX_PATH, "TODO");

	entry->path = (char *)calloc(entry->pathLen + 1, sizeof(char));
	FS_ASSERT_LOG_RETURN(entry->path, "TODO");

	result = fread(entry->path, entry->pathLen, 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	entry->path[entry->pathLen] = '\0';

	result = fread(&entry->hash.buffer, FS_BASE64_DIGEST_SIZE, 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	entry->hash.buffer[FS_BASE64_DIGEST_SIZE - 1] = '\0';

	result = fread(&entry->offset, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fread(&entry->offsetLen, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	return 1;
}

int FS_SaveFileStore(FILE *file) {
	static uint32_t version = 0;
	int result = 0;

	result = fwrite(&version, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	result = fwrite(&fs_State.fsData.snapshotCount, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	for (FS_Snapshot *snapshot = fs_State.fsData.snapshotHead;
		 snapshot != NULL;
		 snapshot = snapshot->next) {

		uint32_t entryListCount = snapshot->entryCount;
		result = fwrite(&entryListCount, sizeof(uint32_t), 1, file);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");

		for (FS_FileEntry *entry = snapshot->entryHead;
			 entry != NULL;
			 entry = entry->snapNext) {
			result = FS_SaveFileEntry(file, entry);
			FS_ASSERT_LOG_RETURN(result == 1, "TODO");
		}
	}

	result = fwrite(&fs_State.fsData.trackingCount, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	for (FS_FileEntry *entry = fs_State.fsData.entryTrackingHead;
		 entry != NULL;
		 entry = entry->trackNext) {
		result = FS_SaveFileEntry(file, entry);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	}

	result = fwrite(&fs_State.fsData.bufferCount, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	if (fs_State.fsData.bufferCount) {
		result = fwrite(fs_State.fsData.buffer, fs_State.fsData.bufferCount, 1, file);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	}

	return 1;
}

int FS_LoadFileStore(FILE *file) {
	uint32_t version = 0;
	int result = 0;

	result = fread(&version, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "Unable to load version to file store");
	FS_ASSERT_LOG_RETURN(version == 0, "Only version 0 supported.");

	uint32_t snapshotCount;
	result = fread(&snapshotCount, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "Unable to load snapshot count to file store");

	for (uint32_t isnap = 0; isnap < snapshotCount; isnap++) {

		FS_Snapshot *snapshot = FS_AllocateSnapshot();
		FS_ASSERT_LOG_RETURN(snapshot, "Unable to use snapshot");

		FS_AddToSnapshotList(snapshot);

		uint32_t entryListCount = 0;
		result = fread(&entryListCount, sizeof(uint32_t), 1, file);
		FS_ASSERT_LOG_RETURN(result == 1, "Unable to load file entry list count from file store");

		for (uint32_t ientry = 0; ientry < entryListCount; ientry++) {

			FS_FileEntry *entry = FS_AllocateFileEntry();
			FS_ASSERT_LOG_RETURN(entry, "Unable to use file entry");

			entry->inSnapshot = 1;

			FS_AddToSnapshotFileEntryList(snapshot, entry);

			result = FS_LoadFileEntry(file, entry);
			FS_ASSERT_LOG_RETURN(result == 1, "TODO");
		}
	}
	
	uint32_t trackingListCount;
	result = fread(&trackingListCount, sizeof(uint32_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");

	for (uint32_t ientry = 0; ientry < trackingListCount; ientry++) {

		FS_FileEntry *entry = FS_AllocateFileEntry();
		FS_ASSERT_LOG_RETURN(entry, "Unable to use file entry");
			
		FS_AddToTrackingList(entry);

		result = FS_LoadFileEntry(file, entry);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	}
	
	result = fread(&fs_State.fsData.bufferCount, sizeof(uint64_t), 1, file);
	FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	FS_ASSERT_LOG_RETURN(fs_State.fsData.bufferCount < 100000, "TODO");

	if (fs_State.fsData.bufferCount) {
		fs_State.fsData.buffer = (char *)calloc(fs_State.fsData.bufferCount, sizeof(char));
		FS_ASSERT_LOG_RETURN(fs_State.fsData.buffer, "TODO");

		result = fread(fs_State.fsData.buffer, fs_State.fsData.bufferCount, 1, file);
		FS_ASSERT_LOG_RETURN(result == 1, "TODO");
	}

	return 1;

}

int FS_Run(int argc, char *argv[]) {

	FS_Sha1Test();

	if (argc <= 1) {
		FS_LOG(
			"The FileStore is a program which takes a set of user supplied files\n"
			"and tracks and stores snapshots of these files within an FileStore file [.fs].\n"
			"Common usage:\n"
			"\"fs create <file store name>\" // creates a file store that you can store files in.\n"
			"\"fs add <file store name> <file to add>\" // adds a file to the file store\n"
		);
		return 1;
	}

	const char *commandStr = argv[1];
	FS_ASSERT_LOG_RETURN(commandStr, "Error. The second argument is a NULL.");

	// Work out what the command is.
	const size_t MAX_COMMAND_LENGTH = 32;

	size_t commandLen = strnlen(commandStr, MAX_COMMAND_LENGTH);

	typedef enum FS_COMMAND {
		FS_CREATE = 0,
		FS_SAVE,
		FS_TRACK,
		FS_RESET,
		FS_SNAPS,
		FS_LOAD,

		FS_COMMAND_COUNT
	} FS_COMMAND;

	FS_COMMAND command = FS_COMMAND_COUNT;

	if (strncmp("create", commandStr, commandLen) == 0) {
		command = FS_CREATE;
	}
	else if (strncmp("save", commandStr, commandLen) == 0) {
		command = FS_SAVE;
	}
	else if (strncmp("track", commandStr, commandLen) == 0) {
		command = FS_TRACK;
	}
	else if (strncmp("reset", commandStr, commandLen) == 0) {
		command = FS_RESET;
	}
	else if (strncmp("snaps", commandStr, commandLen) == 0) {
		command = FS_SNAPS;
	}
	else if (strncmp("load", commandStr, commandLen) == 0) {
		command = FS_LOAD;
	}
	else {
		FS_LOG("This command [%s] is unrecognised. Try \"fv <cheat>\" to a see a list of useful commands, or \"fv <help>\" for some help.", commandStr);
		return 0;
	}

	switch (command) {
	case FS_CREATE: {
		if (argc >= 2) {
			const char *fileName = argv[2];
			FS_ASSERT_LOG_RETURN(fileName, "Error. The third argument is a NULL.");

			// We need to append the .fv suffix;
			char path[FS_MAX_PATH] = {0};

			strncpy(path, fileName, FS_MAX_PATH - 1);
			path[FS_MAX_PATH - 1] = '\0';
			strncat(path, ".fs", FS_MAX_PATH - 1);

			// Check the file exists 
			FILE *file = fopen(path, "rb");
			FS_ASSERT_LOG_RETURN(!file, "The file [%s] already exists. So no file was created.", path);

			file = fopen(path, "wb");
			FS_ASSERT_LOG_RETURN(file, "Unable to create[%s].fs file", path);

			int result = FS_SaveFileStore(file);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(file);
			FS_ASSERT_LOG_RETURN(result == 0, "Unable to close [%s].fv file", path);

			FS_LOG("Sucessfully created the %s file store.", path);
		}
		break;
	}
	case FS_RESET: {

		break;
	}
	case FS_SAVE: {

		if (argc >= 2) {

			const char *fileStoreStr = argv[2];
			FS_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

			FILE *fileStore = fopen(fileStoreStr, "rb");
			FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);

			int result = FS_LoadFileStore(fileStore);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(fileStore);
			FS_ASSERT_LOG_RETURN(result == 0, "TODO");

			if (fs_State.fsData.trackingCount || fs_State.fsData.snapshotCount) {

				FS_Snapshot *snapshot = FS_AllocateSnapshot();

				if (fs_State.fsData.snapshotCount == 0) {

					for (FS_FileEntry *entry = fs_State.fsData.entryTrackingHead;
						 entry != NULL;
						 entry = entry->trackNext) {
						FS_AddToSnapshotFileEntryList(snapshot, entry);
					}
				}
				else {

					FS_Snapshot *lastSnapshot = fs_State.fsData.snapshotTail;
					for (FS_FileEntry *entry = lastSnapshot->entryHead;
						 entry != NULL;
						 entry = entry->snapNext) {

						FS_FileEntry *newEntry = FS_AllocateFileEntry();
						newEntry->offset = entry->offset;
						memcpy(newEntry->hash.buffer, entry->hash.buffer, FS_BASE64_DIGEST_SIZE);
						newEntry->path = (char *)calloc(entry->pathLen + 1, sizeof(char));
						strncpy(newEntry->path, entry->path, entry->pathLen);
						newEntry->path[entry->pathLen] = '\0';
						newEntry->pathLen = entry->pathLen;
						newEntry->offset = entry->offset;
						newEntry->offsetLen = entry->offsetLen;
						newEntry->inSnapshot = 1;

						FS_AddToSnapshotFileEntryList(snapshot, newEntry);
					}

					for (FS_FileEntry *entry = fs_State.fsData.entryTrackingHead;
						 entry != NULL;
						 entry = entry->trackNext) {

						// is it in the new snapshotlist list 
						int isInSnapList = 0;
						for (FS_FileEntry *snapEntry = snapshot->entryHead;
							 snapEntry != NULL;
							 snapEntry = snapEntry->snapNext) {

							if (strncmp(entry->path, snapEntry->path, FS_MAX_PATH) == 0) {
								isInSnapList = 1;
								break;
							}
						}

						if (isInSnapList) {
							FS_AddToSnapshotFileEntryList(snapshot, entry);
						}
					}
				}

				for (FS_FileEntry *entry = snapshot->entryHead;
					 entry != NULL;
					 entry = entry->snapNext) {

					FILE *file = fopen(entry->path, "rb");
					FS_ASSERT_LOG_RETURN(file, "TODO");

					result = FS_AllocateFileContents(file, &entry->buffer, &entry->bufferLen);
					FS_ASSERT_LOG_RETURN(result, "TODO");

					if (entry->inSnapshot) {
						FS_Base64Digest digest = {0};
						result = FS_HashBuffer(&digest, entry->buffer, entry->bufferLen);
						FS_ASSERT_LOG_RETURN(result, "TODO");

						// if the hash changes then we need to save the new buffer
						if (strncmp(digest.buffer, entry->hash.buffer, FS_MAX_PATH) != 0) {
							entry->offset = fs_State.fsData.bufferCount;
							fs_State.fsData.bufferCount += entry->bufferLen;
							entry->offsetLen = entry->bufferLen;

							char *newBuffer = realloc(fs_State.fsData.buffer, fs_State.fsData.bufferCount);
							FS_ASSERT_LOG_RETURN(newBuffer, "TODO");
							fs_State.fsData.buffer = newBuffer;
							memcpy(&fs_State.fsData.buffer[entry->offset], entry->buffer, entry->offsetLen);
						}
					}
					else {
						result = FS_HashBuffer(&entry->hash, entry->buffer, entry->bufferLen);
						FS_ASSERT_LOG_RETURN(result, "TODO");

						entry->offset = fs_State.fsData.bufferCount;
						fs_State.fsData.bufferCount += entry->bufferLen;
						entry->offsetLen = entry->bufferLen;

						char *newBuffer = realloc(fs_State.fsData.buffer, fs_State.fsData.bufferCount);
						FS_ASSERT_LOG_RETURN(newBuffer, "TODO");
						fs_State.fsData.buffer = newBuffer;
						memcpy(&fs_State.fsData.buffer[entry->offset], entry->buffer, entry->offsetLen);
					}
				}

				FS_AddToSnapshotList(snapshot);

				// clear the tracking list
				fs_State.fsData.entryTrackingHead = NULL;
				fs_State.fsData.entryTrackingTail = NULL;
				fs_State.fsData.trackingCount = 0;

				fileStore = fopen(fileStoreStr, "wb");
				FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);

				result = FS_SaveFileStore(fileStore);
				FS_ASSERT_LOG_RETURN(result, "TODO");

				result = fclose(fileStore);
				FS_ASSERT_LOG_RETURN(result == 0, "TODO");

				FS_LOG("Saved new snapshot to the file store.");
			}
			else {
				FS_LOG("There are no currently tracked files that can be saved into this file store");
			}
		}
		break;
	}
	case FS_TRACK: {

		if (argc >= 3) {

			const char *fileStoreStr = argv[2];
			FS_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

			const char *fileTrackStr = argv[3];
			FS_ASSERT_LOG_RETURN(fileTrackStr, "The <fileToTrack> argument is a NULL.");

			size_t strLen = strnlen(fileTrackStr, FS_MAX_PATH);
			FS_ASSERT_LOG_RETURN(strLen, "Unable to open the [%s] file to add.", fileTrackStr);

			FILE *fileStore = fopen(fileStoreStr, "rb");
			FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);
			
			int result = FS_LoadFileStore(fileStore);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(fileStore);
			FS_ASSERT_LOG_RETURN(result == 0, "TODO");

			FILE *fileToTrack = fopen(fileTrackStr, "rb");
			FS_ASSERT_LOG_RETURN(fileToTrack, "Unable to open the [%s] file to add.", fileTrackStr);

			FS_FileEntry *entry = FS_AllocateFileEntry();
			FS_ASSERT_LOG_RETURN(entry, "TODO");

			result = FS_AllocateFileContents(fileToTrack, &entry->buffer, &entry->bufferLen);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = FS_HashBuffer(&entry->hash, entry->buffer, entry->bufferLen);
			FS_ASSERT_LOG_RETURN(result, "TODO");
				
			char *str = (char *)calloc(strLen + 1, sizeof(char));
			FS_ASSERT_LOG_RETURN(str, "Out of memory. Unable to allocate string.");
			strncpy(str, fileTrackStr, strLen);
			str[strLen] = '\0';

			entry->path = str;
			entry->pathLen = strLen;

			FS_AddToTrackingList(entry);

			fileStore = fopen(fileStoreStr, "wb");
			FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);

			result = FS_SaveFileStore(fileStore);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(fileStore);
			FS_ASSERT_LOG_RETURN(result == 0, "TODO");

			
			//result = FS_SaveWorkingAddedFileInFileStore();
			//FS_ASSERT_LOG_RETURN(result, "Unable to save working file.");

			//FS_LOG("The file [%s] was added to the working file.", node->path);
		}
		break;
	}
	case FS_LOAD: {

		if (argc >= 3) {
			const char *fileStoreStr = argv[2];
			FS_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

			FILE *fileStore = fopen(fileStoreStr, "rb");
			FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);

			int result = FS_LoadFileStore(fileStore);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(fileStore);
			FS_ASSERT_LOG_RETURN(result == 0, "TODO");

			const char *snapIndexStr = argv[3];
			FS_ASSERT_LOG_RETURN(snapIndexStr, "The <snapIndex> argument is a NULL.");

			FS_Snapshot *snapshot = fs_State.fsData.snapshotTail;

			for (FS_FileEntry *entry = snapshot->entryHead;
				 entry != NULL;
				 entry = entry->snapNext) {

				FILE *file = fopen(entry->path, "wb");
				FS_ASSERT_LOG_RETURN(file, "TODO");

				int result = fwrite(&fs_State.fsData.buffer[entry->offset], entry->offsetLen, 1, file);
				FS_ASSERT_LOG_RETURN(result == 1, "TODO");

				result = fclose(file);
				FS_ASSERT_LOG_RETURN(result == 0, "TODO");
			}
		}

		break;
	}
	case FS_SNAPS: {

		if (argc >= 3) {
			const char *fileStoreStr = argv[2];
			FS_ASSERT_LOG_RETURN(fileStoreStr, "The <fileStore> argument is a NULL.");

			FILE *fileStore = fopen(fileStoreStr, "rb");
			FS_ASSERT_LOG_RETURN(fileStore, "Unable to open file [%s]", fileStoreStr);

			int result = FS_LoadFileStore(fileStore);
			FS_ASSERT_LOG_RETURN(result, "TODO");

			result = fclose(fileStore);
			FS_ASSERT_LOG_RETURN(result == 0, "TODO");

			if (fs_State.fsData.snapshotCount) {
				int index = fs_State.fsData.snapshotCount - 1;
				for (FS_Snapshot *snap = fs_State.fsData.snapshotTail;
					 snap != NULL;
					 snap = snap->prev) {

					FS_LOG("[%d] Snapshot", index--);
				}
			}
			else {
				FS_LOG("There are no saved snap shots to look at.");
			}
		}
		break;
	}
	}

	return 1;
}


int main(int argc, char *argv[]) {
	int result = FS_Run(argc, argv);
		 
	return result;
};
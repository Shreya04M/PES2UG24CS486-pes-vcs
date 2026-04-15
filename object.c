// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(id_out->hash, &ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (!id_out) return -1;

    const char *type_str;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // Step 1: build the in-memory object buffer: "<type> <size>\0<data>"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || header_len >= (int)sizeof(header)) return -1;

    size_t total_size = (size_t)header_len + 1 + len;
    unsigned char *full = malloc(total_size);
    if (!full) return -1;

    memcpy(full, header, (size_t)header_len);
    full[header_len] = '\0';
    memcpy(full + (size_t)header_len + 1, data, len);

    // Step 2: hash the FULL object (header + '\0' + data)
    compute_hash(full, total_size, id_out);

    // Step 3: deduplication — if we already have this object, we're done.
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Step 4: ensure the shard directory exists (.pes/objects/XX/)
    char path[512];
    object_path(id_out, path, sizeof(path));

    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        free(full);
        return -1;
    }
    *slash = '\0';

    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        free(full);
        return -1;
    }

    // Step 5: write to a temporary file in the shard directory
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char temp_path[576];
    int temp_len = snprintf(temp_path, sizeof(temp_path), "%s/.tmp_%s", dir, hex + 2);
    if (temp_len < 0 || temp_len >= (int)sizeof(temp_path)) {
        free(full);
        return -1;
    }

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full);
        return -1;
    }

    size_t off = 0;
    while (off < total_size) {
        ssize_t n = write(fd, full + off, total_size - off);
        if (n <= 0) {
            close(fd);
            unlink(temp_path);
            free(full);
            return -1;
        }
        off += (size_t)n;
    }

    if (fsync(fd) < 0) {
        close(fd);
        unlink(temp_path);
        free(full);
        return -1;
    }

    if (close(fd) < 0) {
        unlink(temp_path);
        free(full);
        return -1;
    }

    // Step 7: atomically publish the object
    if (rename(temp_path, path) < 0) {
        unlink(temp_path);
        free(full);
        return -1;
    }

    // Step 8: fsync() the shard directory to persist the rename
    int dirfd = open(dir, O_RDONLY);
    if (dirfd < 0) {
        free(full);
        return -1;
    }
    if (fsync(dirfd) < 0) {
        close(dirfd);
        free(full);
        return -1;
    }
    close(dirfd);

    free(full);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (nread != (size_t)sz) {
        free(buf);
        return -1;
    }

    ObjectID actual;
    compute_hash(buf, nread, &actual);
    if (memcmp(&actual, id, sizeof(ObjectID)) != 0) {
        free(buf);
        return -1;
    }

    unsigned char *nul = memchr(buf, '\0', nread);
    if (!nul) {
        free(buf);
        return -1;
    }
    size_t header_len = (size_t)(nul - buf);
    if (header_len == 0 || header_len + 1 > nread) {
        free(buf);
        return -1;
    }

    char *header = malloc(header_len + 1);
    if (!header) {
        free(buf);
        return -1;
    }
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    size_t declared_size = 0;
    int consumed = 0;
    if (sscanf(header, "%15s %zu %n", type_str, &declared_size, &consumed) != 2) {
        free(header);
        free(buf);
        return -1;
    }
    if ((size_t)consumed != header_len) {
        free(header);
        free(buf);
        return -1;
    }
    free(header);

    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    size_t data_len = nread - (header_len + 1);
    if (declared_size != data_len) {
        free(buf);
        return -1;
    }

    void *out = malloc(data_len ? data_len : 1);
    if (!out) {
        free(buf);
        return -1;
    }
    if (data_len) memcpy(out, nul + 1, data_len);
    free(buf);

    *data_out = out;
    *len_out = data_len;
    return 0;
}

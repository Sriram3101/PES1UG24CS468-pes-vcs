/ object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

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

// Phase 1 implementation notes:
// - Always hash the full object bytes: "<type> <size>\0<data>"
// - Use temp-file + fsync + rename for atomic durable writes
// - Verify hash during reads before returning parsed payload

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


int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    FILE *f;
    uint8_t *file_buf = NULL;
    void *payload = NULL;
    long file_size_long;
    size_t file_size;
    uint8_t *nul_pos;
    char type_str[16];
    size_t declared_size;
    size_t header_len;
    size_t payload_len;
    ObjectID computed;

    if (!id || !type_out || !data_out || !len_out) return -1;

    object_path(id, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    file_size_long = ftell(f);
    if (file_size_long < 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    file_size = (size_t)file_size_long;
    file_buf = malloc(file_size);
    if (!file_buf) {
        fclose(f);
        return -1;
    }

    if (file_size > 0 && fread(file_buf, 1, file_size, f) != file_size) {
        free(file_buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    compute_hash(file_buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(file_buf);
        return -1;
    }

    nul_pos = memchr(file_buf, '\0', file_size);
    if (!nul_pos) {
        free(file_buf);
        return -1;
    }

    header_len = (size_t)(nul_pos - file_buf);
    if (header_len == 0 || sscanf((char *)file_buf, "%15s %zu", type_str, &declared_size) != 2) {
        free(file_buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB;
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(file_buf);
        return -1;
    }

    if (header_len + 1 > file_size) {
        free(file_buf);
        return -1;
    }

    payload_len = file_size - (header_len + 1);
    if (declared_size != payload_len) {
        free(file_buf);
        return -1;
    }

    payload = malloc(payload_len > 0 ? payload_len : 1);
    if (!payload) {
        free(file_buf);
        return -1;
    }

    if (payload_len > 0) {
        memcpy(payload, file_buf + header_len + 1, payload_len);
    }

    *data_out = payload;
    *len_out = payload_len;

    free(file_buf);
    return 0;
}



void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

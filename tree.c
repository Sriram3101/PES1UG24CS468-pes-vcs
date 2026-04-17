

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Check whether a path is inside the provided prefix scope.
static int path_in_scope(const char *path, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (prefix_len == 0) return path[0] != '\0';
    return strncmp(path, prefix, prefix_len) == 0;
}

// Extract the next path component after prefix.
// For path="src/lib/main.c" and prefix="src/", this yields name_out="lib", is_dir_out=1.
static int next_component(const char *path, const char *prefix, char *name_out, size_t name_size, int *is_dir_out) {
    const char *rest;
    const char *slash;
    size_t name_len;

    if (!path || !prefix || !name_out || !is_dir_out || name_size == 0) return -1;
    if (!path_in_scope(path, prefix)) return -1;

    rest = path + strlen(prefix);
    if (*rest == '\0') return -1;

    slash = strchr(rest, '/');
    if (slash) {
        name_len = (size_t)(slash - rest);
        *is_dir_out = 1;
    } else {
        name_len = strlen(rest);
        *is_dir_out = 0;
    }

    if (name_len == 0 || name_len >= name_size) return -1;
    memcpy(name_out, rest, name_len);
    name_out[name_len] = '\0';
    return 0;
}

static TreeEntry *tree_find_entry(Tree *tree, const char *name) {
    for (int i = 0; i < tree->count; i++) {
        if (strcmp(tree->entries[i].name, name) == 0) return &tree->entries[i];
    }
    return NULL;
}

static int load_index_snapshot(Index *index) {
    FILE *f;
    char line[1200];

    index->count = 0;
    f = fopen(INDEX_FILE, "r");
    if (!f) return 0;

    while (index->count < MAX_INDEX_ENTRIES && fgets(line, sizeof(line), f) != NULL) {
        IndexEntry *e = &index->entries[index->count];
        char hash_hex[HASH_HEX_SIZE + 1];
        unsigned long long mtime_tmp;
        int rc = sscanf(line, "%o %64s %llu %u %511[^\n]",
                        &e->mode,
                        hash_hex,
                        &mtime_tmp,
                        &e->size,
                        e->path);
        if (rc != 5 || hex_to_hash(hash_hex, &e->hash) != 0) {
            fclose(f);
            return -1;
        }
        e->mtime_sec = (uint64_t)mtime_tmp;
        index->count++;
    }

    fclose(f);
    return 0;
}

static uint32_t normalize_file_mode(uint32_t mode) {
    if (mode == MODE_EXEC) return MODE_EXEC;
    return MODE_FILE;
}

static int write_tree_level(const Index *index, const char *prefix, ObjectID *id_out) {
    Tree tree;
    void *serialized = NULL;
    size_t serialized_len = 0;

    tree.count = 0;

    for (int i = 0; i < index->count; i++) {
        char name[256];
        int is_dir;
        TreeEntry *existing;

        if (next_component(index->entries[i].path, prefix, name, sizeof(name), &is_dir) != 0) {
            continue;
        }

        existing = tree_find_entry(&tree, name);
        if (existing) {
            // Reject ambiguous paths like both "a" and "a/..." in the same tree level.
            if ((is_dir && existing->mode != MODE_DIR) || (!is_dir && existing->mode == MODE_DIR)) {
                return -1;
            }
            continue;
        }

        if (tree.count >= MAX_TREE_ENTRIES) {
            return -1;
        }

        TreeEntry *entry = &tree.entries[tree.count];
        memset(entry, 0, sizeof(*entry));
        snprintf(entry->name, sizeof(entry->name), "%s", name);

        if (is_dir) {
            char child_prefix[768];
            if (snprintf(child_prefix, sizeof(child_prefix), "%s%s/", prefix, name) >= (int)sizeof(child_prefix)) {
                return -1;
            }
            if (write_tree_level(index, child_prefix, &entry->hash) != 0) {
                return -1;
            }
            entry->mode = MODE_DIR;
        } else {
            entry->hash = index->entries[i].hash;
            entry->mode = normalize_file_mode(index->entries[i].mode);
        }

        tree.count++;
    }

    if (tree.count == 0) return -1;

    if (tree_serialize(&tree, &serialized, &serialized_len) != 0) {
        return -1;
    }

    if (object_write(OBJ_TREE, serialized, serialized_len, id_out) != 0) {
        free(serialized);
        return -1;
    }

    free(serialized);
    return 0;
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    Index index;

    if (!id_out) return -1;

    if (load_index_snapshot(&index) != 0) return -1;

    if (index.count == 0) return -1;

    return write_tree_level(&index, "", id_out);
}

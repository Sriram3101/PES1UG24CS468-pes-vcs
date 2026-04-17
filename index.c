

#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// Forward declaration (implemented in object.c)
void hash_to_hex(const ObjectID *id, char *hex_out);
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

static int compare_index_entries(const void *a, const void *b) {
    const IndexEntry *ea = (const IndexEntry *)a;
    const IndexEntry *eb = (const IndexEntry *)b;
    return strcmp(ea->path, eb->path);
}




// ─── PROVIDED ────────────────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
// Returns 0 on success, -1 if path not in index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

// Print the status of the working directory.
//
// Identifies files that are staged, unstaged (modified/deleted in working dir),
// and untracked (present in working dir but not in index).
// Returns 0.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    // Note: A true Git implementation deeply diffs against the HEAD tree here. 
    // For this lab, displaying indexed files represents the staging intent.
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            // Fast diff: check metadata instead of re-hashing file content
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            // Skip hidden directories, parent directories, and build artifacts
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue; // compiled executable
            if (strstr(ent->d_name, ".o") != NULL) continue; // object files

            // Check if file is tracked in the index
            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1; 
                    break;
                }
            }
            
            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) { // Only list regular files for simplicity
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

// Load the index from .pes/index.
//
// HINTS - Useful functions:
//   - fopen (with "r"), fscanf, fclose : reading the text file line by line
//   - hex_to_hash                      : converting the parsed string to ObjectID
//
// Returns 0 on success, -1 on error.
int index_load(Index *index) {
    FILE *f;
    char line[1200];

    if (!index) return -1;
    index->count = 0;

    f = fopen(INDEX_FILE, "r");
    if (!f) {
        // A missing index means "nothing staged yet", not an error.
        return 0;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        IndexEntry *e;
        char hash_hex[HASH_HEX_SIZE + 1];
        unsigned int mode_tmp;
        unsigned long long mtime_tmp;
        int rc;

        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') {
            continue;
        }

        if (index->count >= MAX_INDEX_ENTRIES) {
            fclose(f);
            return -1;
        }

        e = &index->entries[index->count];
        rc = sscanf(line, "%o %64s %llu %u %511[^\n]",
                    &mode_tmp,
                    hash_hex,
                    &mtime_tmp,
                    &e->size,
                    e->path);
        if (rc != 5 || hex_to_hash(hash_hex, &e->hash) != 0) {
            fclose(f);
            return -1;
        }

        if (strlen(e->path) == 0 || strlen(e->path) >= sizeof(e->path)) {
            fclose(f);
            return -1;
        }

        e->mode = (uint32_t)mode_tmp;
        e->mtime_sec = (uint64_t)mtime_tmp;
        index->count++;
    }

    fclose(f);
    return 0;
}

// Save the index to .pes/index atomically.
//
// HINTS - Useful functions and syscalls:
//   - qsort                            : sorting the entries array by path
//   - fopen (with "w"), fprintf        : writing to the temporary file
//   - hash_to_hex                      : converting ObjectID for text output
//   - fflush, fileno, fsync, fclose    : flushing userspace buffers and syncing to disk
//   - rename                           : atomically moving the temp file over the old index
//
// Returns 0 on success, -1 on error.
int index_save(const Index *index) {
    Index *sorted;
    FILE *f;
    int dir_fd;
    char hex[HASH_HEX_SIZE + 1];
    char tmp_path[sizeof(INDEX_FILE) + 8];

    if (!index) return -1;
    if (index->count < 0 || index->count > MAX_INDEX_ENTRIES) return -1;

    sorted = malloc(sizeof(Index));
    if (!sorted) return -1;
    *sorted = *index;
    qsort(sorted->entries, sorted->count, sizeof(IndexEntry), compare_index_entries);

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE);
    f = fopen(tmp_path, "w");
    if (!f) {
        free(sorted);
        return -1;
    }

    for (int i = 0; i < sorted->count; i++) {
        const IndexEntry *e = &sorted->entries[i];
        hash_to_hex(&e->hash, hex);
        if (fprintf(f, "%o %s %llu %u %s\n",
                    e->mode,
                    hex,
                    (unsigned long long)e->mtime_sec,
                    e->size,
                    e->path) < 0) {
            fclose(f);
            unlink(tmp_path);
            free(sorted);
            return -1;
        }
    }

    if (fflush(f) != 0) {
        fclose(f);
        unlink(tmp_path);
        free(sorted);
        return -1;
    }
    if (fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp_path);
        free(sorted);
        return -1;
    }
    if (fclose(f) != 0) {
        unlink(tmp_path);
        free(sorted);
        return -1;
    }

    if (rename(tmp_path, INDEX_FILE) != 0) {
        unlink(tmp_path);
        free(sorted);
        return -1;
    }

    // Persist the rename in the parent directory metadata.
    dir_fd = open(PES_DIR, O_RDONLY);
    if (dir_fd >= 0) {
        if (fsync(dir_fd) != 0) {
            close(dir_fd);
            free(sorted);
            return -1;
        }
        close(dir_fd);
    }

    free(sorted);
    return 0;
}

// Stage a file for the next commit.
//
// HINTS - Useful functions and syscalls:
//   - fopen, fread, fclose             : reading the target file's contents
//   - object_write                     : saving the contents as OBJ_BLOB
//   - stat / lstat                     : getting file metadata (size, mtime, mode)
//   - index_find                       : checking if the file is already staged
//
// Returns 0 on success, -1 on error.
int index_add(Index *index, const char *path) {
    struct stat st;
    FILE *f;
    void *data = NULL;
    size_t read_len;
    ObjectID blob_id;
    IndexEntry *entry;

    if (!index || !path) return -1;
    if (index->count >= MAX_INDEX_ENTRIES && !index_find(index, path)) return -1;
    if (strlen(path) == 0 || strlen(path) >= sizeof(index->entries[0].path)) return -1;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > UINT32_MAX) {
        return -1;
    }

    f = fopen(path, "rb");
    if (!f) return -1;

    if (st.st_size > 0) {
        data = malloc((size_t)st.st_size);
        if (!data) {
            fclose(f);
            return -1;
        }
        read_len = fread(data, 1, (size_t)st.st_size, f);
        if (read_len != (size_t)st.st_size) {
            free(data);
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    if (object_write(OBJ_BLOB, data, (size_t)st.st_size, &blob_id) != 0) {
        free(data);
        return -1;
    }
    free(data);

    entry = index_find(index, path);
    if (!entry) {
        entry = &index->entries[index->count++];
        memset(entry, 0, sizeof(*entry));
    }

    entry->hash = blob_id;
    entry->mtime_sec = (uint64_t)st.st_mtime;
    entry->size = (uint32_t)st.st_size;
    entry->mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;
    snprintf(entry->path, sizeof(entry->path), "%s", path);

    return index_save(index);
}

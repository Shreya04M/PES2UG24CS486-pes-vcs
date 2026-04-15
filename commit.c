// commit.c — Commit creation and history traversal
//
// Commit object format (stored as text, one field per line):
//
//   tree <64-char-hex-hash>
//   parent <64-char-hex-hash>        ← omitted for the first commit
//   author <name> <unix-timestamp>
//   committer <name> <unix-timestamp>
//
//   <commit message>
//
// Note: there is a blank line between the headers and the message.
//
// PROVIDED functions: commit_parse, commit_serialize, commit_walk, head_read, head_update
// TODO functions:     commit_create

#include "commit.h"
#include "index.h"
#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

// Forward declarations (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

// Parse raw commit data into a Commit struct.
int commit_parse(const void *data, size_t len, Commit *commit_out) {
    (void)len;
    const char *p = (const char *)data;
    char hex[HASH_HEX_SIZE + 1];

    // "tree <hex>\n"
    if (sscanf(p, "tree %64s\n", hex) != 1) return -1;
    if (hex_to_hash(hex, &commit_out->tree) != 0) return -1;
    p = strchr(p, '\n') + 1;

    // optional "parent <hex>\n"
    if (strncmp(p, "parent ", 7) == 0) {
        if (sscanf(p, "parent %64s\n", hex) != 1) return -1;
        if (hex_to_hash(hex, &commit_out->parent) != 0) return -1;
        commit_out->has_parent = 1;
        p = strchr(p, '\n') + 1;
    } else {
        commit_out->has_parent = 0;
    }

    // "author <name> <timestamp>\n"
    char author_buf[256];
    uint64_t ts;
    if (sscanf(p, "author %255[^\n]\n", author_buf) != 1) return -1;
    // split off trailing timestamp
    char *last_space = strrchr(author_buf, ' ');
    if (!last_space) return -1;
    ts = (uint64_t)strtoull(last_space + 1, NULL, 10);
    *last_space = '\0';
    strncpy(commit_out->author, author_buf, sizeof(commit_out->author) - 1);
    commit_out->timestamp = ts;
    p = strchr(p, '\n') + 1;  // skip author line
    p = strchr(p, '\n') + 1;  // skip committer line
    p = strchr(p, '\n') + 1;  // skip blank line

    strncpy(commit_out->message, p, sizeof(commit_out->message) - 1);
    return 0;
}

// Serialize a Commit struct to the text format.
// Caller must free(*data_out).
int commit_serialize(const Commit *commit, void **data_out, size_t *len_out) {
    char tree_hex[HASH_HEX_SIZE + 1];
    char parent_hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&commit->tree, tree_hex);

    char buf[8192];
    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "tree %s\n", tree_hex);
    if (commit->has_parent) {
        hash_to_hex(&commit->parent, parent_hex);
        n += snprintf(buf + n, sizeof(buf) - n, "parent %s\n", parent_hex);
    }
    n += snprintf(buf + n, sizeof(buf) - n,
                  "author %s %" PRIu64 "\n"
                  "committer %s %" PRIu64 "\n"
                  "\n"
                  "%s",
                  commit->author, commit->timestamp,
                  commit->author, commit->timestamp,
                  commit->message);

    *data_out = malloc(n + 1);
    if (!*data_out) return -1;
    memcpy(*data_out, buf, n + 1);
    *len_out = (size_t)n;
    return 0;
}

// Walk commit history from HEAD to the root.
int commit_walk(commit_walk_fn callback, void *ctx) {
    ObjectID id;
    if (head_read(&id) != 0) return -1;

    while (1) {
        ObjectType type;
        void *raw;
        size_t raw_len;
        if (object_read(&id, &type, &raw, &raw_len) != 0) return -1;

        Commit c;
        int rc = commit_parse(raw, raw_len, &c);
        free(raw);
        if (rc != 0) return -1;

        callback(&id, &c, ctx);

        if (!c.has_parent) break;
        id = c.parent;
    }
    return 0;
}

// Read the current HEAD commit hash.
int head_read(ObjectID *id_out) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0'; // strip newline

    char ref_path[512];
    if (strncmp(line, "ref: ", 5) == 0) {
        snprintf(ref_path, sizeof(ref_path), "%s/%s", PES_DIR, line + 5);
        f = fopen(ref_path, "r");
        if (!f) return -1; // Branch exists but has no commits yet
        if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
        fclose(f);
        line[strcspn(line, "\r\n")] = '\0';
    }
    return hex_to_hash(line, id_out);
}

// Update the current branch ref to point to a new commit atomically.
int head_update(const ObjectID *new_commit) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';

    char target_path[512];
    if (strncmp(line, "ref: ", 5) == 0) {
        snprintf(target_path, sizeof(target_path), "%s/%s", PES_DIR, line + 5);
    } else {
        snprintf(target_path, sizeof(target_path), "%s", HEAD_FILE); // Detached HEAD
    }

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", target_path);
    
    f = fopen(tmp_path, "w");
    if (!f) return -1;
    
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(new_commit, hex);
    fprintf(f, "%s\n", hex);
    
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    
    return rename(tmp_path, target_path);
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

// Create a new commit from the current staging area.
//
// HINTS - Useful functions to call:
//   - tree_from_index   : writes the directory tree and gets the root hash
//   - head_read         : gets the parent commit hash (if any)
//   - pes_author        : retrieves the author name string (from pes.h)
//   - time(NULL)        : gets the current unix timestamp
//   - commit_serialize  : converts the filled Commit struct to a text buffer
//   - object_write      : saves the serialized text as OBJ_COMMIT
//   - head_update       : moves the branch pointer to your new commit
//
// Returns 0 on success, -1 on error.
int commit_create(const char *message, ObjectID *commit_id_out) {
    if (!message || !commit_id_out) return -1;

    ObjectID root_tree;
    if (tree_from_index(&root_tree) != 0) return -1;

    Commit c;
    memset(&c, 0, sizeof(c));
    c.tree = root_tree;

    ObjectID parent;
    if (head_read(&parent) == 0) {
        c.parent = parent;
        c.has_parent = 1;
    } else {
        c.has_parent = 0;
    }

    snprintf(c.author, sizeof(c.author), "%s", pes_author());
    c.timestamp = (uint64_t)time(NULL);
    snprintf(c.message, sizeof(c.message), "%s", message);

    void *raw = NULL;
    size_t raw_len = 0;
    if (commit_serialize(&c, &raw, &raw_len) != 0) return -1;

    ObjectID commit_id;
    int rc = object_write(OBJ_COMMIT, raw, raw_len, &commit_id);
    free(raw);
    if (rc != 0) return -1;

    if (head_update(&commit_id) != 0) return -1;

    *commit_id_out = commit_id;
    return 0;
}

// ─── CLI commands (needed by pes.c) ───────────────────────────────────────

static int ensure_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static int write_file_atomic(const char *path, const char *contents) {
    char tmp[512];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return -1;
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    if (fprintf(f, "%s", contents) < 0) { fclose(f); unlink(tmp); return -1; }
    if (fflush(f) != 0) { fclose(f); unlink(tmp); return -1; }
    if (fsync(fileno(f)) != 0) { fclose(f); unlink(tmp); return -1; }
    if (fclose(f) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

void cmd_init(void) {
    if (ensure_dir(PES_DIR, 0755) != 0) {
        fprintf(stderr, "error: failed to create %s\n", PES_DIR);
        return;
    }
    if (ensure_dir(OBJECTS_DIR, 0755) != 0) {
        fprintf(stderr, "error: failed to create %s\n", OBJECTS_DIR);
        return;
    }
    if (ensure_dir(".pes/refs", 0755) != 0) {
        fprintf(stderr, "error: failed to create .pes/refs\n");
        return;
    }
    if (ensure_dir(REFS_DIR, 0755) != 0) {
        fprintf(stderr, "error: failed to create %s\n", REFS_DIR);
        return;
    }

    if (write_file_atomic(HEAD_FILE, "ref: refs/heads/main\n") != 0) {
        fprintf(stderr, "error: failed to write %s\n", HEAD_FILE);
        return;
    }

    // Ensure the main branch file exists (may remain empty until first commit)
    int fd = open(".pes/refs/heads/main", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}

void cmd_add(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pes add <file>...\n");
        return;
    }

    Index *idx = malloc(sizeof(*idx));
    if (!idx) {
        fprintf(stderr, "error: out of memory\n");
        return;
    }

    if (index_load(idx) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        free(idx);
        return;
    }

    for (int i = 2; i < argc; i++) {
        if (index_add(idx, argv[i]) != 0) {
            fprintf(stderr, "error: failed to add '%s'\n", argv[i]);
            free(idx);
            return;
        }
    }

    free(idx);
}

void cmd_status(void) {
    Index *idx = malloc(sizeof(*idx));
    if (!idx) {
        fprintf(stderr, "error: out of memory\n");
        return;
    }
    if (index_load(idx) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        free(idx);
        return;
    }
    (void)index_status(idx);
    free(idx);
}

void cmd_commit(int argc, char *argv[]) {
    const char *msg = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            msg = argv[i + 1];
            break;
        }
    }
    if (!msg) {
        fprintf(stderr, "Usage: pes commit -m <msg>\n");
        return;
    }

    ObjectID id;
    if (commit_create(msg, &id) != 0) {
        fprintf(stderr, "error: commit failed\n");
        return;
    }

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);
    printf("Committed %s\n", hex);
}

static void log_callback(const ObjectID *id, const Commit *commit, void *ctx) {
    (void)ctx;
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    printf("commit %s\n", hex);
    printf("Author: %s\n", commit->author);
    printf("Date:   %" PRIu64 "\n\n", commit->timestamp);
    printf("    %s\n\n", commit->message);
}

void cmd_log(void) {
    if (commit_walk(log_callback, NULL) != 0) {
        fprintf(stderr, "error: no commits yet\n");
    }
}

// ─── Branch + checkout (minimal implementations) ─────────────────────────

int branch_list(void) {
    DIR *d = opendir(REFS_DIR);
    if (!d) return -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        printf("%s\n", ent->d_name);
    }
    closedir(d);
    return 0;
}

int branch_create(const char *name) {
    if (!name || !name[0]) return -1;
    if (strchr(name, '/') != NULL) return -1;

    if (ensure_dir(".pes/refs", 0755) != 0) return -1;
    if (ensure_dir(REFS_DIR, 0755) != 0) return -1;

    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", REFS_DIR, name) >= (int)sizeof(path)) return -1;

    // Write current HEAD commit (if any), else create empty branch file.
    ObjectID head;
    if (head_read(&head) == 0) {
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&head, hex);
        char buf[80];
        snprintf(buf, sizeof(buf), "%s\n", hex);
        return write_file_atomic(path, buf);
    }

    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

int branch_delete(const char *name) {
    if (!name || !name[0]) return -1;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", REFS_DIR, name) >= (int)sizeof(path)) return -1;
    return unlink(path);
}

int checkout(const char *target) {
    if (!target || !target[0]) return -1;

    // If a branch exists, switch HEAD to that symbolic ref.
    char ref_path[512];
    if (snprintf(ref_path, sizeof(ref_path), "%s/%s", REFS_DIR, target) < (int)sizeof(ref_path)) {
        if (access(ref_path, F_OK) == 0) {
            char head_contents[512];
            if (snprintf(head_contents, sizeof(head_contents), "ref: refs/heads/%s\n", target) >= (int)sizeof(head_contents)) return -1;
            return write_file_atomic(HEAD_FILE, head_contents);
        }
    }

    // Otherwise, treat as commit hash (detached HEAD).
    if (strlen(target) != HASH_HEX_SIZE) return -1;
    for (size_t i = 0; i < HASH_HEX_SIZE; i++) {
        char c = target[i];
        int is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!is_hex) return -1;
    }

    char buf[80];
    snprintf(buf, sizeof(buf), "%s\n", target);
    return write_file_atomic(HEAD_FILE, buf);
}
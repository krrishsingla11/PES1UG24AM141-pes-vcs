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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
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
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
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
 // 1. Map the ObjectType enum back to a string for the header
    const char *type_str;
    if (type == OBJ_BLOB) {
        type_str = "blob";
    } else if (type == OBJ_TREE) {
        type_str = "tree";
    } else if (type == OBJ_COMMIT) {
        type_str = "commit";
    } else {
        return -1; // Unknown type fallback
    }

    // 2. Create the header: "<type> <len>\0"
    char header[128];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    
    // Total size includes header, null terminator (+1), and the actual data length
    size_t full_size = header_len + 1 + len; 

    // 3. Combine header and data into a single buffer
    unsigned char *full_buffer = malloc(full_size);
    if (!full_buffer) return -1; // Catch memory allocation failures

    memcpy(full_buffer, header, header_len + 1); // Copy header + \0
    if (data && len > 0) {
        memcpy(full_buffer + header_len + 1, data, len); // Copy actual data
    }

    // 4. Compute SHA-256 hash of the combined buffer
    unsigned char raw_hash[SHA256_DIGEST_LENGTH];
    SHA256(full_buffer, full_size, raw_hash);

    // Save the raw hash into the output parameter your professor provided
    if (id_out) {
        memcpy(id_out, raw_hash, SHA256_DIGEST_LENGTH);
    }

    // Convert raw hash bytes to a hexadecimal string so we can use it for file names
    char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_hash + (i * 2), "%02x", raw_hash[i]);
    }

    // 5. Determine paths for sharding
    char dir_path[256];
    char final_path[512];
    snprintf(dir_path, sizeof(dir_path), ".pes/objects/%.2s", hex_hash);
    snprintf(final_path, sizeof(final_path), "%s/%s", dir_path, hex_hash + 2);

    // 6. Create the shard directory (it's okay if it already exists)
    mkdir(dir_path, 0777); 

    // 7. Write atomically (temp file -> rename)
    char temp_path[] = ".pes/objects/temp_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd == -1) {
        free(full_buffer);
        return -1; // Error creating temp file
    }

    // Write to the temp file (checking the return value to silence compiler warnings)
    if (write(fd, full_buffer, full_size) != (ssize_t)full_size) {
        close(fd);
        free(full_buffer);
        return -1; // Error during write
    }
    close(fd);

    // Atomically move the temporary file to its final destination
    rename(temp_path, final_path);

    free(full_buffer);
    return 0; // Success
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
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
// 1. Convert the ObjectID struct to a hex string using the built-in helper
    char hash_hex[65];
    hash_to_hex(id, hash_hex); 

    // 2. Reconstruct the file path from the hex hash
    char path[512];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash_hex, hash_hex + 2);

    // 3. Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1; // File not found

    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    
    // We check the return value of fread to fix the compiler warning you got
    if (fread(buffer, 1, file_size, f) != file_size) {
        free(buffer);
        fclose(f);
        return -1; 
    }
    fclose(f);

    // 4. Verify Integrity (Recompute hash and compare)
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    SHA256(buffer, file_size, computed_hash);

    char computed_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(computed_hash_hex + (i * 2), "%02x", computed_hash[i]);
    }

    // If the hashes don't match, the file is corrupted!
    if (strcmp(computed_hash_hex, hash_hex) != 0) {
        free(buffer);
        return -1; // Integrity check failed
    }

    // 5. Parse the header to extract type and size ("type size\0")
    char *space_pos = strchr((char *)buffer, ' ');
    char *null_pos = strchr((char *)buffer, '\0');

    if (!space_pos || !null_pos || space_pos > null_pos) {
        free(buffer);
        return -1; // Malformed header
    }

    // Extract the type string
    size_t type_len = space_pos - (char *)buffer;
    char type_str[32];
    memcpy(type_str, buffer, type_len);
    type_str[type_len] = '\0';

    // Map the string back to your ObjectType enum
    // *NOTE*: Check pes.h to confirm if your enums are named OBJ_BLOB, or TYPE_BLOB, etc.
    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB; 
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    }

    // 6. Extract the size (this maps to your specific len_out parameter)
    *len_out = strtoul(space_pos + 1, NULL, 10);

    // 7. Extract the data payload (everything after the \0)
    *data_out = malloc(*len_out);
    memcpy(*data_out, null_pos + 1, *len_out);

    free(buffer);
    return 0; // Success
}

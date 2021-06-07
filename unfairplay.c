#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>

extern int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

int copy(const char* src, const char* dest) {
    if (strcmp(src, dest) == 0) {
        return 1;
    }

    int result = 0;
    FILE* src_fp = fopen(src, "rb");
    FILE* dest_fp = fopen(dest, "wb");
    if (src_fp == NULL || dest_fp == NULL) {
        result = 1;
    }

    if (result != 1) {
        while (1) {
            char c;
            if (fread(&c, sizeof(c), 1, src_fp) < 1) {
                if (feof(src_fp)) {
                    break;
                } else {
                    result = 1;
                    break;
                }
            }
            if (fwrite(&c, sizeof(c), 1, dest_fp) < 1) {
                result = 1;
                break;
            }
        }
    }

    if (dest_fp != NULL) {
        if (fclose(dest_fp) == EOF) {
            result = 1;
        }
    }
    if (src_fp != NULL) {
        if (fclose(src_fp) == EOF) {
            result = 1;
        }
    }

    return result;
}

static int unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info) {
    void *base = mmap(NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int error = mremap_encrypted(base, info->cryptsize, info->cryptid,
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (error) {
        perror("mremap_encrypted");
        printf("Please wait 1 second and try it again.\n");
        munmap(base, info->cryptsize);
        return 1;
    }

    memcpy(dupe + info->cryptoff, base, info->cryptsize);

    munmap(base, info->cryptsize);
    return 0;
}

static uint8_t* map(const char *path, bool mutable, size_t *size, int *descriptor) {
    int f = open(path, mutable ? O_RDWR : O_RDONLY);
    if (f < 0) {
        perror("open");
        return NULL;
    }

    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat");
        close(f);
        return NULL;
    }

    uint8_t *base = mmap(NULL, s.st_size, mutable ? PROT_READ | PROT_WRITE : PROT_READ,
        mutable ? MAP_SHARED : MAP_PRIVATE, f, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        close(f);
        return NULL;
    }

    *size = s.st_size;
    if (descriptor) {
        *descriptor = f;
    } else {
        close(f);
    }
    return base;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s src dest\n", argv[0]);
        return 1;
    }

    size_t base_size;
    int f;
    uint8_t *base = map(argv[1], false, &base_size, &f);
    if (base == NULL) {
        return 1;
    }

    if (copy(argv[1], argv[2]) == 1) {
        perror("copy");
        return 1;
    }

    size_t dupe_size;
    uint8_t *dupe = map(argv[2], true, &dupe_size, NULL);
    if (dupe == NULL) {
        munmap(base, base_size);
        return 1;
    }

    // If the files are not of the same size, then they are not duplicates of
    // each other, which is an error.
    //
    if (base_size != dupe_size) {
        munmap(base, base_size);
        munmap(dupe, dupe_size);
        return 1;
    }

    struct mach_header_64* header = (struct mach_header_64*) base;
    assert(header->magic == MH_MAGIC_64);
    assert(header->cputype == CPU_TYPE_ARM64);
    assert(header->cpusubtype == CPU_SUBTYPE_ARM64_ALL);

    uint32_t offset = sizeof(struct mach_header_64);

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 *encryption_info =
                (struct encryption_info_command_64*) command;
            // If "unprotect"'ing is successful, then change the "cryptid" so that
            // the loader does not attempt to decrypt decrypted pages.
            //
            if (unprotect(f, dupe, encryption_info) == 0) {
                encryption_info = (struct encryption_info_command_64*) (dupe + offset);
                encryption_info->cryptid = 0;
            }
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);

    printf("Succeeded in decrypting the binary.\n");

    return 0;
}

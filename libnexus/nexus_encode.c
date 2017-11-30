/**
 * This is derived from the encryptfs source code.
 * It encodes the filename in a baae64-style encoding.
 *
 * See fs/ecryptfs/crypto.c in a Linux Kernel tree
 */
#include <stdlib.h>
#include <string.h>

#include "nexus_internal.h"

/* 64 characters forming a 6-bit target field */
char portable_filename_chars[] = ("-.0123456789ABCD"
                                  "EFGHIJKLMNOPQRST"
                                  "UVWXYZabcdefghij"
                                  "klmnopqrstuvwxyz");

/* We could either offset on every reverse map or just pad some 0x00's
 * at the front here */
static const unsigned char filename_rev_map[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
    0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
    0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
    0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
    0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
    0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
    0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
    0x3D, 0x3E, 0x3F /* 123 - 255 initialized to 0x00 */
};

/**
 * ecryptfs_encode_for_filename
 * @dst: Destination location for encoded filename
 * @dst_size: Size of the encoded filename in bytes
 * @src: Source location for the filename to encode
 * @src_size: Size of the source in bytes
 */
static void
ecryptfs_encode_for_filename(unsigned char * dst,
                             size_t *        dst_size,
                             unsigned char * src,
                             size_t          src_size)
{
    size_t        num_blocks;
    size_t        block_num  = 0;
    size_t        dst_offset = 0;
    unsigned char last_block[3];

    if (src_size == 0) {
        (*dst_size) = 0;
        goto out;
    }
    num_blocks = (src_size / 3);
    if ((src_size % 3) == 0) {
        memcpy(last_block, (&src[src_size - 3]), 3);
    } else {
        num_blocks++;
        last_block[2] = 0x00;
        switch (src_size % 3) {
        case 1:
            last_block[0] = src[src_size - 1];
            last_block[1] = 0x00;
            break;
        case 2:
            last_block[0] = src[src_size - 2];
            last_block[1] = src[src_size - 1];
        }
    }
    (*dst_size) = (num_blocks * 4);
    if (!dst)
        goto out;
    while (block_num < num_blocks) {
        unsigned char * src_block;
        unsigned char   dst_block[4];

        if (block_num == (num_blocks - 1))
            src_block = last_block;
        else
            src_block = &src[block_num * 3];
        dst_block[0]  = ((src_block[0] >> 2) & 0x3F);
        dst_block[1]
            = (((src_block[0] << 4) & 0x30) | ((src_block[1] >> 4) & 0x0F));
        dst_block[2]
            = (((src_block[1] << 2) & 0x3C) | ((src_block[2] >> 6) & 0x03));
        dst_block[3]      = (src_block[2] & 0x3F);
        dst[dst_offset++] = portable_filename_chars[dst_block[0]];
        dst[dst_offset++] = portable_filename_chars[dst_block[1]];
        dst[dst_offset++] = portable_filename_chars[dst_block[2]];
        dst[dst_offset++] = portable_filename_chars[dst_block[3]];
        block_num++;
    }
out:
    return;
}

static size_t
ecryptfs_max_decoded_size(size_t encoded_size)
{
    /* Not exact; conservatively long. Every block of 4
     * encoded characters decodes into a block of 3
     * decoded characters. This segment of code provides
     * the caller with the maximum amount of allocated
     * space that @dst will need to point to in a
     * subsequent call. */
    return ((encoded_size + 1) * 3) / 4;
}

/**
 * ecryptfs_decode_from_filename
 * @dst: If NULL, this function only sets @dst_size and returns. If
 *       non-NULL, this function decodes the encoded octets in @src
 *       into the memory that @dst points to.
 * @dst_size: Set to the size of the decoded string.
 * @src: The encoded set of octets to decode.
 * @src_size: The size of the encoded set of octets to decode.
 */
static void
ecryptfs_decode_from_filename(unsigned char *       dst,
                              size_t *              dst_size,
                              const unsigned char * src,
                              size_t                src_size)
{
    uint8_t current_bit_offset = 0;
    size_t  src_byte_offset    = 0;
    size_t  dst_byte_offset    = 0;

    if (dst == NULL) {
        (*dst_size) = ecryptfs_max_decoded_size(src_size);
        goto out;
    }
    while (src_byte_offset < src_size) {
        unsigned char src_byte = filename_rev_map[(int)src[src_byte_offset]];

        switch (current_bit_offset) {
        case 0:
            dst[dst_byte_offset] = (src_byte << 2);
            current_bit_offset   = 6;
            break;
        case 6:
            dst[dst_byte_offset++] |= (src_byte >> 4);
            dst[dst_byte_offset] = ((src_byte & 0xF) << 4);
            current_bit_offset   = 4;
            break;
        case 4:
            dst[dst_byte_offset++] |= (src_byte >> 2);
            dst[dst_byte_offset] = (src_byte << 6);
            current_bit_offset   = 2;
            break;
        case 2:
            dst[dst_byte_offset++] |= (src_byte);
            dst[dst_byte_offset] = 0;
            current_bit_offset   = 0;
            break;
        }
        src_byte_offset++;
    }
    (*dst_size) = dst_byte_offset;
out:
    return;
}

size_t global_encoded_str_size = 0;

void
compute_encoded_str_size()
{
    struct uuid code;
    ecryptfs_encode_for_filename(
        NULL, &global_encoded_str_size, (uint8_t *)&code, sizeof(struct uuid));
}

static char *
encode_bin2str(const struct uuid * code, char * prefix, size_t prefix_len)
{
    char * result = NULL;
    size_t sz;

    result = (char *)calloc(1, prefix_len + global_encoded_str_size + 1);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, prefix, prefix_len);
    ecryptfs_encode_for_filename(
        (uint8_t *)result + prefix_len, &sz, (uint8_t *)code, sizeof(struct uuid));

    result[sz] = '\0';
    return result;
}

static struct uuid *
encode_str2bin(const char * encoded_filename, char * prefix, size_t prefix_len)
{
    size_t       src_sz = strlen(encoded_filename);
    size_t       i, dst_sz;
    const char * _encoded_fname;

    if (src_sz > prefix_len) {
        for (i = 0; i < prefix_len; i++) {
            // if it's not prefixed, don't even bother
            if (encoded_filename[i] != prefix[i]) {
                return NULL;
            }
        }
    } else {
        // we know it's not a valid filename
        return NULL;
    }

    _encoded_fname = encoded_filename + prefix_len;
    src_sz -= prefix_len;

    dst_sz = ecryptfs_max_decoded_size(src_sz);
    if (dst_sz < sizeof(struct uuid)) {
        return NULL;
    }

    struct uuid * code = (struct uuid *)malloc(sizeof(struct uuid) + 1);
    if (code == NULL) {
        return NULL;
    }

    ecryptfs_decode_from_filename(
        (uint8_t *)code, &dst_sz, (uint8_t *)_encoded_fname, src_sz);

    return code;
}

char *
metaname_bin2str(const struct uuid * bin)
{
    return encode_bin2str(
        bin, NEXUS_METANAME_PREFIX, NEXUS_PREFIX_SIZE(NEXUS_METANAME_PREFIX));
}

struct uuid *
metaname_str2bin(const char * str)
{
    return encode_str2bin(
        str, NEXUS_METANAME_PREFIX, NEXUS_PREFIX_SIZE(NEXUS_METANAME_PREFIX));
}

char *
filename_bin2str(const struct uuid * bin)
{
    return encode_bin2str(
        bin, NEXUS_FILENAME_PREFIX, NEXUS_PREFIX_SIZE(NEXUS_FILENAME_PREFIX));
}

struct uuid *
filename_str2bin(const char * str)
{
    return encode_str2bin(
        str, NEXUS_FILENAME_PREFIX, NEXUS_PREFIX_SIZE(NEXUS_FILENAME_PREFIX));
}

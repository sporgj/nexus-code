#include "attribute_table.h"

#include "../libnexus_trusted/hashmap.h"


struct __attr_table_hdr {
    size_t                  count;
    size_t                  generation;

    __mac_and_version_bytes_t attribute_space_macversion_bytes;
} __attribute__((packed));


struct __attr_table_entry {
    struct nexus_uuid attr_uuid;
    size_t            attr_val_len;
    char              attr_val[ATTRIBUTE_VALUE_SIZE];
} __attribute__((packed));



// adding and removing entries from the attribute table's hashmap

static struct attribute_entry *
__put_attr_entry(struct attribute_table * attribute_table,
                 struct nexus_uuid *      uuid,
                 char *                   value,
                 size_t                   len)
{
    struct attribute_entry * new_entry = NULL;

    if (len > ATTRIBUTE_VALUE_SIZE) {
        log_error("attribute value is too large (got=%zu, max=%zu)\n", len, ATTRIBUTE_VALUE_SIZE);
        return NULL;
    }

    new_entry = nexus_malloc(sizeof(struct attribute_entry));

    memcpy(new_entry->attr_val, value, len);
    new_entry->attr_val_len = len;

    hashmap_entry_init(&new_entry->hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &new_entry->attr_uuid);

    hashmap_add(&attribute_table->attribute_map, &new_entry->hash_entry);

    attribute_table->count += 1;

    return new_entry;
}

static int
__del_attr_entry(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    struct attribute_entry * rst_entry = NULL;
    struct attribute_entry   tmp_entry;

    hashmap_entry_init(&tmp_entry.hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &tmp_entry.attr_uuid);

    rst_entry = hashmap_remove(&attribute_table->attribute_map, &tmp_entry, NULL);
    if (rst_entry == NULL) {
        return -1;
    }

    nexus_free(rst_entry);

    attribute_table->count -= 1;

    return 0;
}

static struct attribute_entry *
__get_attr_entry(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    struct attribute_entry tmp_entry;

    hashmap_entry_init(&tmp_entry.hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &tmp_entry.attr_uuid);

    return (struct attribute_entry *)hashmap_get(&attribute_table->attribute_map, &tmp_entry, NULL);
}

const char *
attribute_table_find(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    struct attribute_entry * entry = __get_attr_entry(attribute_table, uuid);

    if (entry == NULL) {
        return NULL;
    }

    return entry->attr_val;
}

int
attribute_table_add(struct attribute_table * attribute_table,
                    struct nexus_uuid      * uuid,
                    char                   * value)
{
    struct attribute_entry * entry = __get_attr_entry(attribute_table, uuid);

    size_t len = strnlen(value, ATTRIBUTE_VALUE_SIZE);

    if (entry) {
        if (strncmp(entry->attr_val, value, ATTRIBUTE_VALUE_SIZE) == 0) {
            return 0;
        }

        if (len == 0) {
            memset(entry->attr_val, 0, ATTRIBUTE_VALUE_SIZE);
        } else {
            memcpy(entry->attr_val, value, len);
        }

        entry->attr_val_len = len;
    } else {
        entry = __put_attr_entry(attribute_table, uuid, value, len);
    }

    attribute_table->generation += 1;

    return 0;
}

int
attribute_table_del(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    if (__del_attr_entry(attribute_table, uuid)) {
        return -1;
    }

    attribute_table->generation += 1;

    return 0;
}


static int
__attribute_htable_cmp(const void *                   data,
                       const struct attribute_entry * entry1,
                       const struct attribute_entry * entry2,
                       const void *                   keydata)
{
    return nexus_uuid_compare(&entry1->attr_uuid, &entry2->attr_uuid);
}

static void
attribute_table_init(struct attribute_table * attribute_table)
{
    hashmap_init(&attribute_table->attribute_map, (hashmap_cmp_fn)__attribute_htable_cmp, NULL, 0);
}

struct attribute_table *
attribute_table_create()
{
    struct attribute_table * attribute_table = nexus_malloc(sizeof(struct attribute_table));

    attribute_table_init(attribute_table);

    return attribute_table;
}

void
attribute_table_free(struct attribute_table * attribute_table)
{
    hashmap_free(&attribute_table->attribute_map, true);
    nexus_free(attribute_table);
}


static uint8_t *
__parse_attribute_table_hdr(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_hdr * header = (struct __attr_table_hdr *)buffer;

    attribute_table->count = header->count;
    attribute_table->generation = header->generation;

    __mac_and_version_from_buf(&attribute_table->attribute_space_macversion,
                               (uint8_t *)&header->attribute_space_macversion_bytes);

    return buffer + sizeof(struct __attr_table_hdr);
}

static int
__parse_attribute_table_body(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_entry * input_entry = (struct __attr_table_entry *)buffer;

    size_t count = attribute_table->count;

    attribute_table->count = 0; // __put_attr_entry increments the count

    for (size_t i = 0; i < count; i++) {
        if (__put_attr_entry(attribute_table,
                             &input_entry->attr_uuid,
                             input_entry->attr_val,
                             input_entry->attr_val_len) == NULL) {
            log_error("__put_attr_entry FAILED\n");
            return -1;
        }

        input_entry += 1;
    }

    return 0;
}

struct attribute_table *
attribute_table_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct attribute_table * attribute_table = NULL;

    if (buflen < sizeof(struct __attr_table_hdr)) {
        log_error("attribute_table buffer is too small (len=%zu, min=%zu)\n",
                  buflen,
                  sizeof(struct __attr_table_hdr));

        return NULL;
    }

    attribute_table = nexus_malloc(sizeof(struct attribute_table));

    attribute_table_init(attribute_table);

    buffer = __parse_attribute_table_hdr(attribute_table, buffer);

    if (__parse_attribute_table_body(attribute_table, buffer)) {
        log_error("__parse_attribute_table_body FAILED\n");
        attribute_table_free(attribute_table);
        return NULL;
    }

    return attribute_table;
}

size_t
attribute_table_get_size(struct attribute_table * attribute_table)
{
    return sizeof(struct __attr_table_hdr)
           + (attribute_table->count * sizeof(struct __attr_table_entry));
}


/// serializes the attribute table's header into the buffer and returns the buffer shifted
static uint8_t *
__serialize_attribute_header(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_hdr * dest_header = (struct __attr_table_hdr *)buffer;

    dest_header->count = attribute_table->count;
    dest_header->generation = attribute_table->generation;

    __mac_and_version_to_buf(&attribute_table->attribute_space_macversion,
                             (uint8_t *)&dest_header->attribute_space_macversion_bytes);

    return buffer + sizeof(struct __attr_table_hdr);
}

static uint8_t *
__serialize_attribute_entry(struct attribute_entry * attribute_entry, uint8_t * buffer)
{
    struct __attr_table_entry * dest_entry = (struct __attr_table_entry *)buffer;

    nexus_uuid_copy(&attribute_entry->attr_uuid, &dest_entry->attr_uuid);
    dest_entry->attr_val_len = attribute_entry->attr_val_len;
    memcpy(dest_entry->attr_val, attribute_entry->attr_val, attribute_entry->attr_val_len);

    return (buffer + sizeof(struct __attr_table_entry));
}

int
attribute_table_store(struct attribute_table * attribute_table, uint8_t * buffer, size_t buflen)
{
    struct hashmap_iter iter;

    size_t total_len = attribute_table_get_size(attribute_table);

    if (buflen < total_len) {
        log_error("attribute_table buffer too small. (got=%zu, min=%zu)\n", buflen, total_len);
        return -1;
    }

    // update the mac version
    if (abac_global_export_macversion(&attribute_table->attribute_space_macversion)) {
        log_error("could not export mac version\n");
        return -1;
    }

    buffer = __serialize_attribute_header(attribute_table, buffer);

    hashmap_iter_init(&attribute_table->attribute_map, &iter);

    do {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);

        if (attr_entry == NULL) {
            break;
        }

        buffer = __serialize_attribute_entry(attr_entry, buffer);
    } while (1);

    return 0;
}

int
attribute_table_export_facts(struct attribute_table * attribute_table,
                             struct attribute_space * attribute_space,
                             char                   * first_term,
                             rapidstring            * string_builder,
                             size_t                 * p_skip_count)
{
    const struct attribute_schema * attr_term;

    struct hashmap_iter iter;

    size_t skip_count = 0;

    hashmap_iter_init(&attribute_table->attribute_map, &iter);

    do {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);
        if (attr_entry == NULL) {
            break;
        }

        attr_term = attribute_space_find_uuid(attribute_space, &attr_entry->attr_uuid);
        if (attr_term == NULL) {
            // TODO maybe report here?
            skip_count += 1;
            continue;
        }

        // append the fact to the string_builder
        rs_cat(string_builder, attr_term->name);
        rs_cat_n(string_builder, "(", 1);
        rs_cat(string_builder, first_term);
        rs_cat_n(string_builder, ", \"", 3);
        rs_cat(string_builder, attr_entry->attr_val);
        rs_cat_n(string_builder, "\").\n", 4);
    } while(1);

    *p_skip_count = skip_count;

    return 0;
}

int
UNSAFE_attribute_table_ls(struct attribute_table    * attribute_table,
                          struct attribute_space    * attribute_space,
                          struct nxs_attribute_pair * attribute_pair_array,
                          size_t                      attribute_pair_capacity,
                          size_t                      offset,
                          size_t                    * result_count,
                          size_t                    * total_count)
{
    struct hashmap_iter iter;

    struct nxs_attribute_pair * output_pair_ptr = attribute_pair_array;

    struct attribute_schema * tmp_attribute_schema = NULL;

    size_t copied = 0;


    hashmap_iter_init(&attribute_table->attribute_map, &iter);

    do {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);

        if (offset) {
            offset -= 1;
            continue;
        }

        if (attr_entry == NULL) {
            break;
        }

        // copy out the attribute pair
        tmp_attribute_schema = attribute_space_find_uuid(attribute_space, &attr_entry->attr_uuid);

        if (tmp_attribute_schema) {
            // then copy its name into the pair
            strncpy(output_pair_ptr->schema_str, tmp_attribute_schema->name, NXS_ATTRIBUTE_NAME_MAX);
        } else {
            // XXX: temporaray
            strncpy(output_pair_ptr->schema_str, "XXX", NXS_ATTRIBUTE_NAME_MAX);
        }

        strncpy(output_pair_ptr->val_str, attr_entry->attr_val, NXS_ATTRIBUTE_VALUE_MAX);

        copied += 1;
        output_pair_ptr += 1;
    } while (copied < attribute_pair_capacity);

    *result_count = copied;
    *total_count = attribute_table->count;

    return 0;
}

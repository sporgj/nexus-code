#pragma once



/* Supernode Structure 

   - Crypto context
      - [16 bytes] encryption key
      - [16 bytes] encryption iv
      - [16 bytes] tag???
      - [16 bytes] ekey_mac ????
      
   - Header
      - uuid ???
      - root_uuid ???
      - version ????
      - total_size : size of the entire supernode structure
      - owner : hash of the owners public key

   - user table
      - [4 bytes] user_count  : Total number of user entries
      - [4 bytes] user_buflen : total size of user entry list
      - [0-N bytes] array of variable sized user entries
      
      user entry:
          - [16 bytes] hash of user's public key 
          - [2 bytes]  length of username
	  - [0-M bytes] username



 */


struct crypto_context {
    crypto_ekey_t ekey;
    uint8_t       iv[CONFIG_IV_BYTES];
    uint8_t       tag[CONFIG_TAG_BYTES];
    uint8_t       ekey_mac[CONFIG_EKEY_BYTES];
};


struct pubkey_hash {
    uint8_t bytes[CONFIG_HASH_BYTES];
};




struct user_entry {
    struct pubkey_hash pubkey;
    uint16_t namelen;
    uint8_t  name[0];
};

struct volume_user_table {
    uint32_t          user_count;
    uint32_t          user_buflen;
    struct user_entry user_list[0];
};

struct supernode_header {
    struct uuid        uuid;
    struct uuid        root_uuid;
    version_t          version;
    uint32_t           total_size;
    struct pubkey_hash owner;
} __attribute__((packed));

struct supernode {
    struct crypto_context    crypto_context;
    struct supernode_header  header;
    struct volume_user_table user_table;
} __attribute__((packed));



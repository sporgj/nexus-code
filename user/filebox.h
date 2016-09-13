#pragma once
#include <fstream>

extern "C" {
#include "types.h"
}

#include "fbox.pb.h"

class fbox;

class FileBox {
private:
    fbox_header_t header;
    fbox * proto = nullptr;

public:
    FileBox();
    static FileBox * from_file(const char * fpath);
    static FileBox * from_afs_file(const char * fpath);
    static bool write(FileBox * fb, std::fstream * file);

    encoded_fname_t * create_segment();
    crypto_context_t * segment_crypto(uint32_t seg_id);
    encoded_fname_t * segment_name(uint32_t seg_id);
};

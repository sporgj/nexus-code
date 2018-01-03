#pragma once



// buffers sealed with the enclave crypto context e.g. volumekey
struct sealed_buffer {
    size_t size;
    void * untrusted_addr;
};


// encrypted data buffers


// encrytped data file buffer 

struct datafile_buffer {
    size_t size;
    void * untrusted_addr;
};


provider backend_sgx {
    probe ecall_start(int);
    probe ecall_finish(int);
    probe iobuf_start(int);
    probe iobuf_finish(int);
};

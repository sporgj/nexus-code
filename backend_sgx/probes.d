provider backend_sgx {
    probe ecall__start(char * op);

    probe ecall__finish();
}

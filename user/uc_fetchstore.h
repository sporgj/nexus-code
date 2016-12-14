#ifdef __cplusplus
extern "C" {
#endif

int
fetchstore_start(uc_xfer_op_t op,
            char * fpath,
            uint16_t max_xfer_size,
            uint32_t offset,
            uint32_t file_size,
            int old_fbox_len,
            int * xfer_id,
            int * new_fbox_len);

uint8_t **
fetchstore_get_buffer(int id, size_t valid_buflen);

int
fetchstore_data(uint8_t ** buffer);

int
fetchstore_finish(int id);

int
fetchstore_fbox(int fbox_inout, uint8_t ** buffer);


int
store_start(char * fpath,
            uint16_t max_xfer_size,
            uint32_t offset,
            uint32_t file_size,
            int old_fbox_len,
            int * xfer_id,
            int * new_fbox_len);

uint8_t **
store_get_buffer(int id, size_t valid_buflen);

int
store_data(uint8_t ** buffer);

int
store_finish(int id);

int
store_fbox(int fbox_inout, uint8_t ** buffer);

#ifdef __cplusplus
}
#endif

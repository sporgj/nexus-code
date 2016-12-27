#ifdef __cplusplus
extern "C" {
#endif

int
fetchstore_init(xfer_req_t * rq, char * fpath, xfer_rsp_t * rp);

int
fetchstore_run(int id, size_t valid_buflen);

int
fetchstore_finish(int id);

#ifdef __cplusplus
}
#endif

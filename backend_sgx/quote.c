#include "internal.h"

#include <nexus_encode.h>

#include <curl/curl.h>

sgx_quote_t *
generate_quote(sgx_report_t * report, uint32_t * p_quote_size)
{
    sgx_quote_t * quote      = NULL;

    uint32_t      quote_len  = 0;

    int           ret        = -1;


    ret = sgx_calc_quote_size(NULL, 0, &quote_len);

    if (ret) {
        log_error("sgx_get_quote_size FAILED (ret=%x)\n", ret);
        return NULL;
    }

    quote = nexus_malloc(quote_len);

    ret = sgx_get_quote(report, SGX_UNLINKABLE_SIGNATURE, &global_spid, NULL,
                        NULL, 0, NULL, quote, quote_len);

    if (ret) {
        log_error("sgx_get_quote FAILED (ret=%x)\n", ret);
        goto err;
    }

    *p_quote_size = quote_len;

    return quote;

err:
    if (quote) {
        nexus_free(quote);
    }

    return NULL;
}

int
validate_quote(sgx_quote_t * quote, uint32_t quote_size)
{
    char *   base64_quote = NULL;

    uint32_t json_len     = 1024;

    char *   json_body    = nexus_malloc(json_len);

    int ret = 0;


    base64_quote = nexus_base64_encode((uint8_t *)quote, quote_size);

    if (base64_quote == NULL) {
        printf("Error: Could not encode quote to base64\n");
        return -1;
    }


    ret = asprintf(&json_body, "{\"isvEnclaveQuote\":\"%s\"}", base64_quote);

    if (ret == -1) {
        nexus_free(base64_quote);

        printf("Error: Could not create JSON request\n");
        return -1;
    }


    {
        CURL *   curl_ctx     = NULL;
        CURLcode curl_res     = 0;


        curl_ctx = curl_easy_init();

        if (curl_ctx == NULL) {
            printf("Error: Could not initialize curl\n");
            goto err;
        }

        curl_easy_setopt(curl_ctx, CURLOPT_URL, SGX_VERIFY_URL);
        curl_easy_setopt(curl_ctx, CURLOPT_SSLCERT, SGX_CERT_PATH);
        curl_easy_setopt(curl_ctx, CURLOPT_SSLKEY, SGX_KEY_PATH);
        curl_easy_setopt(curl_ctx, CURLOPT_KEYPASSWD, SGX_KEY_PASS);

        curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDSIZE, strlen(json_body));
        curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDS, json_body);

        curl_res = curl_easy_perform(curl_ctx);

        // FIXME: return code as quote check failure
        nexus_printf("Verifying Quote, res = %d", (int)curl_res);

        curl_easy_cleanup(curl_ctx);
    }

    free(base64_quote);
    free(json_body);

    return 0;

err:
    free(base64_quote);
    free(json_body);

    return -1;
}

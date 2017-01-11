#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "cdefs.h"
#include "third/sds.h"
#include "third/linenoise.h"

#include "ucafs_header.h"
#include "uc_supernode.h"

#include "mbedtls/pk.h"

const char * repo_fname = "repo.datum";

static char repo_path[1024];

supernode_t * super = NULL;

static int shell()
{
	char * line;

	while ((line = linenoise("> ")) != NULL) {
		if (line[0] != '\0' && line[0] != '/') {
			linenoiseHistoryAdd(line);
		}

		free(line);
	}

	return 0;
}

/**
 * We will parse the public in PEM format
 * @param path is the path to load from
 * @return 0 on success
 */
static int new_supernode(const char * path)
{
	int err = -1;
	mbedtls_pk_context _ctx, * pk_ctx = &_ctx;

	mbedtls_pk_init(pk_ctx);

	if (mbedtls_pk_parse_public_keyfile(pk_ctx, path)) {
		uerror("mbedtls_pk_parse_public_keyfile returned an error");
		return -1;
	}

	err = 0;
out:
	return err;
}

int main() {
	int ret, err, nbytes;
	FILE * fd1, * fd2;
	struct stat st;
	sds repo_file;

	fd1 = fopen(repo_fname, "rb");
	if (fd1 == NULL) {
		uerror("Could not open '%s'", repo_fname);
		return -1;
	}

	nbytes = fread(repo_path, 1, sizeof(repo_path), fd1);
	repo_path[strlen(repo_path) - 1] = '\0';

	/* 2 - Check if the repository exists */
	repo_file = sdsnew(repo_path);
	repo_file = sdscat(repo_file, "/");
	repo_file = sdscat(repo_file, UCAFS_REPO_FNAME);

	err = stat(repo_file, &st);
	if (err) {
		if ((super = superblock_new()) == NULL) {
			uerror("superblock_new() returned NULL");
			return -1;
		}

		if (!superblock_flush(super, repo_file)) {
			uerror("superblock_flush() failed");
			return -1;
		}
	}

	uinfo("Startup complete... :)");
	/* send the user to the cmd */
	shell();

	fclose(fd1);
	sdsfree(repo_file);
	return ret;
}

#pragma once


struct nexus_metadata;
struct nexus_dentry;


int
hashtree_init();

void
hashtree_destroy();

int
hashtree_update(struct nexus_metadata * metadata);

int
hashtree_verify(struct nexus_dentry * dentry);

#pragma once


int
hashtree_init();

void
hashtree_destroy();

int
hashtree_update(struct nexus_dentry * parent_dentry,
                struct nexus_uuid   * child_uuid,
                struct nexus_mac    * child_mac);

int
hashtree_verify(struct nexus_dentry * dentry);

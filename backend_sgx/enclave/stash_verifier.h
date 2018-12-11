#pragma once

// author Judicael Djoko <jbriand@cs.pitt.edu>


int
stashv_init();


void
stashv_destroy();


int
stashv_update(struct nexus_metadata * metadata);


int
stashv_verify(struct nexus_metadata * metadata);

int
stashv_drop(struct nexus_uuid * uuid);

int
stashv_delete(struct nexus_uuid * uuid);

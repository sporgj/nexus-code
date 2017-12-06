#pragma once



int
nexus_fetch_data(struct afs_conn       * tc,
		 struct rx_connection  * rx_conn,
		 struct osi_file       * osi_filp,
		 afs_size_t              base,
		 struct dcache         * dcache,
		 struct vcache         * vcache,
		 afs_int32_t             size,
		 struct rx_call        * acall,
		 char                  * path);



int
nexus_store_data(struct vcache         * vcache,
		 struct dcache         * dcache_list,
		 afs_size_t              num_bytes,
		 afs_hyper_t           * anewDV,
		 int                   * doProcessFS,
		 struct AFSFetchStatus * fetch_status,
		 afs_uint32              chunk_cnt,
		 int                     nomore,
		 struct rx_call        * afs_call,
		 char                  * path,
		 int                     base,
		 struct storeOps       * store_ops,
		 void                  * rock);
		 

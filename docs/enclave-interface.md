# Enclave Interface
## Volume Management
Presumably this should all be called from the admin utility.

+ **Invariants**
    + `supernode` is encrypted before copying to untrusted memory
    + `root_dirnode` encrypted before going to untrusted memory
    + `rootkey` is sealed before copying to untrusted memory


### CreateVolume
Creates a new NeXUS volume.

```c
/**
 * @param pubkey is the user's public key
 * @param supernode destination pointer for supernode
 * @param root_dirnode is the root dirnode
 * @param rootkey is the rootkey aassociated to the rootkey
 */
CreateVolume(
    [in] char * pubkey,
    [out] supernode_t * supernode,
    [out] dirnode_t * root_dirnode,
    [out] rootkey_t * rootkey
)
```

### LoginVolume
Authenticates a user into a volume. This is how one establishes their identity
with the enclave.

```c
/**
 * Application requests authentication token from enclave.
 * @param rootkey is the rootkey to unseal in the enclave
 * @param nonce is the random challenge from the enclave
 */
AuthResquest([in] rootkey_t * rootkey, [out] nonce_t * nonce)

/**
 * Application signs the supernode and nonce
 * @param supernode is the supernode to authenticate into.
 * @param signature is the signature of the supernode and the nonce.
 */
AuthResponse([in] supernode_t * supernode, [out] uint8_t * signature)
```

* **Enclave Checks**
    + Supernode is not tampered
    + Signature matches. Verified with public key in supernode

The supernode is kept in the enclave; its public key is used as the current
user's identity.

### AddUser
Adds a user to the volume.

```c
AddUser(
    [in] supernode_t * supernode,
    [in] char * username,
    [in] uint8_t * public_key
)
```

* **Enclave Checks**
    + user is logged-in
    + user is owner of supernode (public key matching)

### DeleteUser
Removes a user from the volume. Takes name and public key as argument. Will
first attempt to delete by name, then by public key.

```c
DeleteUser(
    [inout] supernode_t * supernode,
    [in] char * username,
    [in] uint8_t * public_key
)
```

* **Enclave Checks**
    + user is logged-in
    + user is owner of supernode (public key matching)

### ListUsers
Lists Users in the volume. Returns a list of users/public key pairs.

```c
/**
 * @param supernode
 * @param usertable is a list of <username, public key> pairs
 */
ListsUsers(
    [in] supernode_t * supernode
    [out] usertable_t * usertable
)
```
* **Enclave Checks**
    + user is logged-in
    + user is owner of supernode (public key matching)

## Dirnode
TODO


## Filenode
TODO


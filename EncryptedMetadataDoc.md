# Encrypting Sensitive Metadata
Using GNU Privacy Guard (https://gnupg.org/) via the python wrapper (https://github.com/vsajip/python-gnupg) sensitive metadata can be encrypted as PGP blocks readable only by specified recipients (specified via `encryptedTo`).

RO-Crate’s that encrypt metadata require a valid GPG binary installed on the system. The location of this binary may be specified by the parameter `gpg_binary` otherwise system default locations are used, for example: `/usr/bin/gpg` for Ubuntu.

These options for saving and reading encrypted metadata are entirely optional and will only be used when encrypted data is present and fingerprints are provided.


##  Encrypting metadata
Sensitive metadata should be saved as part of an  [`EncryptedContextEntity`](rocrate/model/encryptedcontextentity.py) which extends a ContextEntitiy. Encrypted context entities work identically to context entities but also store gpg public key fingerprints, and will have their jsonLD written as encrypted PGP blocks instead of part of the “@graph” when saving the RO-Crate.
These can be read back into readable metadata entities with the appropriate gpg private key, added back to the ROcrate and then used in-memory just like any other context entity.

## Structure of a crate containing encrypted metadata
When creating an RO-Crate object a list of gpg public key fingerprints may be specified using the `pubkey_fingerprints` parameter. These will be used as encryption keys for all Encrypted Context Entities found within the RO-Crate.


Upon writing the crate all encrypted context entities that share a set of encryption fingerprints are aggregated and their jsonLD as it would appear in the RO-Crate are encrypted and saved as a pgp block encrypted to all keys specified in their fingerprint.
These blocks are saved in a dictionary keyed by comma separated gpg fingerprints used to encrypt that data (so that the metadata may be re-encrypted to the same keys in future).

This dictionary of encrypted blocks is then saved at the top level of the crate’s jsonLD as “@encrypted” alongside “@graph” and “@context”.

The structure of an encrypted RO-Crate is then as follows

```json
{
"@context": "https://w3id.org/ro/crate/1.1/context",
“graph”:[ "<unencrypted RO-Crate as normal …>"],
“@encrypted”:[
	{
    	"<GPG Fingerprints separated by comma>":"<PGP encrypted message>",

    	"93B72373820DDB104BC6859474CBFBAB503F3CF3": "-----BEGIN PGP MESSAGE-----\n\nhF4DV/haefcwdMcSAQdApAhbIHhN3Icxu9X05MBw+yqxR8nIiVYUHz5mkErzGWMw\nQgS7rwT5jS9ZXVXDnTDLlzy2o8IqRR4dRg6Dk1k5ehYDO1J4nxXhgUsbyZaNZ4nt\n1MB+AQkCEKpxDSgn3bEzN603n6/3YQZiahteHCU/DTVVAZiU/6+mWrpSt9M5ggHZ\nzfbx1/X2KldsjadparJSdQ1kO1O7raC7zzYVh6o2sQw/8Qgz9tMNgZV5vbqBMpul\nQ9zlq06zrslSYyG3xluqnFIOZ1777yd7f/WNJmrN6mEbQLkKTO2jmOKwGhLrkf+j\nujudPy/6SDAM/D6whss770MNxhuQididDH/CXlFuypI95mXvBunIofN70pYlJZ+y\n/5+xRkpf3k1DO6b5p9WFt1/nuQEu+irXnGqz0d60CIOPmdDkqlI0a2P7EPiJnluB\n6CzSv7HlTHuBf5xChu4iYyqbN4bVjzA57C5jqZTrB7oVsvNcCLltTlsMe9Oym4F0\n1mlqmpPzKUZoLjGlnT+P6VU3uSFSXTY9o9Nb5m4xyj82\n=KtXM\n-----END PGP MESSAGE-----\n",

    	“643BE0B0159AEFC2B9428D578533F9C66A9E7628,93B72373820DDB104BC6859474CBFBAB503F3CF3”:"-----BEGIN PGP MESSAGE-----\n\nhF4DV/haefcwdMcSAQdApAhbIHhN3Icxu9X05MBw+yqxR8nIiVYUHz5mkErzGWMw\nQgS7rwT5jS9ZXVXDnTDLlzy2o8IqRR4dRg6Dk1k5ehYDO1J4nxXhgUsbyZaNZ4nt\n1MB+AQkCEKpxDSgn3bEzN603n6/3YQZiahteHCU/DTVVAZiU/6+mWrpSt9M5ggHZ\nzfbx1/X2KldsjadparJSdQ1kO1O7raC7zzYVh6o2sQw/8Qgz9tMNgZV5vbqBMpul\nQ9zlq06zrslSYyG3xluqnFIOZ1777yd7f/WNJmrN6mEbQLkKTO2jmOKwGhLrkf+j\nujudPy/6SDAM/D6whss770MNxhuQididDH/CXlFuypI95mXvBunIofN70pYlJZ+y\n/5+xRkpf3k1DO6b5p9WFt1/nuQEu+irXnGqz0d60CIOPmdDkqlI0a2P7EPiJnluB\n6CzSv7HlTHuBf5xChu4iYyqbN4bVjzA57C5jqZTrB7oVsvNcCLltTlsMe9Oym4F0\n1mlqmpPzKUZoLjGlnT+P6VU3uSFSXTY9o9Nb5m4xyj82\n=KtXM\n-----END PGP MESSAGE-----\n"

	}
],
}
```
## Reading the encrypted RO-Crate
When reading an RO-Crate that has an “@encrypted” section in its jsonLD all encrypted blocks that are able to be decrypted using gpg keys on the user’s system are decrypted and added to the crate as Encrypted Context Entities. These may be read manipulated and then re-saved as encrypted data or changed to another type and saved as plaintext jsonLD.

Encrypted blocks that cannot be decrypted are not read and are not saved in memory or subsequent RO-Crates to avoid conflicting metadata being stored in encrypted blocks.

## Using these functions
To write an encrypted crate, use `rocrate.write()` for a crate that contains EncryptedContextEntity and `pubkey_fingerprints` specified for the crate or each EncryptedContextEntity.

To read an encrypted crate create an `ROCrate()` object with a ro-crate-metadata.json `source` that contains an ' `"@encrypted"` section of its jsonLD.

Both require the appropriate public or private keys for encryption/decryption and a valid gpg binary installed on the current system.

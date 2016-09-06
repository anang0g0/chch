# chch

Command line tool that encrypts and decrypts files using ChaCha20-Poly1305 (with Argon2i key deriviation).

## Usage

Encrypt stdin to stdout using passphrase `12345`:

```
chch --encrypt --pass 12345 < myfile.txt > myfile.enc
```

or with pipes:

```
cat myfile.txt | gzip | chch -e -p 12345 > myfile.gz.enc
```

Decrypting to stdout:

```
chch -d -p 12345 < myfile.enc
```

You can read the passphrase from a file by prefixing the passphrase argument with `@`:

```
chch -e -p @passphrase.txt < myfile.txt > myfile.enc
```


## File Format

Encrypted output files start with a 48-byte header followed by 1 or more encrypted blocks ("messages" in the sense of [RFC 7539](https://tools.ietf.org/html/rfc7539#section-4) section 4).

Here is the file header:

```
+----------------------------+----------+--------+----------------------------------+
| Field                      | Type     | Offset | Notes                            |
+----------------------------+----------+--------+----------------------------------+
| mark                       | byte[4]  | 0      | "chch"                           |
| version                    | uint32   | 4      | 1 (always)                       |  
| block_size                 | uint32   | 8      | in kilobytes                     |
| _pad                       | n/a      | 12     | (all zeros)                      |
| salt                       | byte[16] | 16     | For Argon2i key derivation       |
| crypto_pwhash_opslimit     | uint64   | 32     | For Argon2i key derivation       |
| crypto_pwhash_memlimit     | size_t   | 40     | For Argon2i key derivation       |
| [Zero'th ciphertext block] | size_t   | 48     | (start of encrypted data)        |
+----------------------------+----------+--------+----------------------------------+
```

The remainder of the file consists of 1 or more blocks, which are variable-length chunks of ciphertext each prefixed with its length and a Poly1305 message authentication (MAC) tag.

Here is the format of each block:

```
+----------------------------+----------+--------+----------------------------------+
| Field                      | Type     | Offset | Notes                            |
+----------------------------+----------+--------+----------------------------------+
| len                        | uint64   | 0      | len of (tag+ciphertext)          |
| tag                        | byte[16] | 8      | Poly1305 tag (MAC)               |  
| ciphertext                 | char[]   | 24     | (ciphertext data)                |
+----------------------------+----------+--------+----------------------------------+
```

## Theory of Operation

**TODO:  write me**

Points to cover:
* Key and nonce derivation from passphrase, salt (how gen'd), Argon2i
* How block_size is chosen (up to 2^70 bytes); maximum size (2^96 messages)
	* Meaning of "message" vs "block"
	* Pros/cons of long and short block sizes
	* Buffering
* Aspirations:
	* adopt RCF 7539 standard
		* use its test vectors
	* add AES-GCM for x68
	* each message should be padded
	* literature references to back up assertions in this readme
	* unit tests
	* better test vectors
	* clarify that this is just a wrapper around implementations in [libsodium](https://github.com/jedisct1/libsodium)
	* explicitly define threat model
* Would appreciate feedback:  [mike@goelzer.com](mailto:mike@goelzer.com)


#include <fcntl.h>      // open
#include <sys/types.h>  // open
#include <sys/stat.h>   // open
#include <unistd.h>     // read, write, close
#include <errno.h>      // errno
#include <ctype.h>      // isspace
#include <assert.h>     // assert
#include <string.h>     // memset
#include <stdio.h>      // printf
#include <inttypes.h>   // PRI[x,u,d]64 format specifiers
#include <sodium.h>     // libsodium
#include <getopt.h>     // gnu getopt_long
#include <stdbool.h>    // bool type

// Output logging
#define LOG_ERROR	1
#define LOG_WARN	2
#define LOG_INFO	4
#define LOG_TRACE	8
static int g_loglevel = LOG_ERROR | LOG_WARN;
#define logerror(format,...) do{ if(g_loglevel&LOG_ERROR)fprintf(stderr, "ERROR: " format, ##__VA_ARGS__); }while(0)
#define logwarn(format,...)  do{ if(g_loglevel&LOG_WARN)fprintf(stderr, "WARN:  " format, ##__VA_ARGS__); }while(0)
#define loginfo(format,...)  do{ if(g_loglevel&LOG_INFO)fprintf(stderr, "INFO:  " format, ##__VA_ARGS__); }while(0)
#define logtrace(format,...) do{ if(g_loglevel&LOG_TRACE)fprintf(stderr, "TRACE: " format, ##__VA_ARGS__); }while(0)

// Crypto parameters
#define SALT_LEN crypto_pwhash_SALTBYTES
static_assert(SALT_LEN==16,"Expected 128-bit salt");
#define KEY_LEN 32
#define NONCE_LEN 8

#define MSG_BLOCK_LEN_KB 1

typedef struct {
	unsigned char key[KEY_LEN];
	union {
		unsigned char nonce_s[NONCE_LEN];
		uint64_t nonce_i;
	};
} key_nonce_t;
static_assert(sizeof(key_nonce_t)==(KEY_LEN+NONCE_LEN),
		"Expecting two strings in a struct to be packed");

int derive_key(
	char const * const p_password, 
	size_t const password_len, 
	unsigned char const * const salt, 
	key_nonce_t* p_out, 
	size_t const out_maxlen,
	uint64_t const crypto_pwhash_opslimit,
	size_t const crypto_pwhash_memlimit) 
{
	assert(out_maxlen==sizeof(key_nonce_t));

	int ret;
	ret = crypto_pwhash(
		(unsigned char*)p_out,
		sizeof(key_nonce_t),
		p_password,
		password_len,
		salt,
		crypto_pwhash_opslimit,
		crypto_pwhash_memlimit,
		crypto_pwhash_ALG_DEFAULT
		);
	if (ret != 0) {
		logerror("crypto_pwhash() failed with %d\n",ret);
	}

	return 0;
}

size_t rtrim(char * s, size_t const len) {
	char c;
	size_t retlen = len;
	while (retlen>0) {
		c = s[retlen-1];
		if (isspace(c)) {
			s[retlen-1]='\0';
			retlen--;
		} else {
			break;
		}
	};
	return retlen;
}

int get_passphrase(char * p_passphrase, size_t * p_len, size_t const max_len) {
	// Order to try:  ./.passphrase (maybe others later)
	int fd;
       	fd = open("./.passphrase", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	*p_len = read(fd, p_passphrase, max_len);
	*p_len = rtrim(p_passphrase,*p_len);
	close(fd);
	return 0;
}

// Returns (initial_nonce + msg_num)
static_assert( sizeof(uint64_t)==NONCE_LEN , "Expecting 64-bit nonce");
void get_msg_nonce(
		const unsigned char * const initial_nonce,
		uint64_t const msg_num,
		unsigned char * const msg_nonce
		) 
{
	memcpy((void*)msg_nonce, (void*)initial_nonce, NONCE_LEN);
	sodium_add((unsigned char *)msg_nonce, (const unsigned char *)&msg_num, NONCE_LEN);
}

static_assert(sizeof(unsigned long long)==8, "encrypt_msg_block_to_stdout: Expecting unsigned long long to be 8 bytes");
static_assert(sizeof(size_t)==8, "encrypt_msg_block_to_stdout: Expecting size_t to be 8 bytes");
static_assert(sizeof(uint64_t)==8, "encrypt_msg_block_to_stdout: Expecting uint64_t to be 8 bytes");
static_assert(crypto_aead_chacha20poly1305_NPUBBYTES==8, "encrypt_msg_block_to_stdout: Expecting 64-bit nonces for ChaCha20");
int encrypt_msg_block_to_stdout(
		const key_nonce_t * const p_key_nonce,
		const unsigned char * const p_inbuf,
		size_t const inbuf_len,
		unsigned char * const p_outbuf,
		size_t const outbuf_len,
		const uint64_t msg_num
) 
{
	// Format of each message block
	// struct {
	//   uint64_t      len of (tag+ciphertext)
	//   char[16]      tag
	//   char[]        ciphertext
	// }
	unsigned char msg_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
	get_msg_nonce(p_key_nonce->nonce_s, msg_num, msg_nonce);
	loginfo("msg 0x%" PRIx64 ": initial nonce 0x%" PRIx64 ", curr nonce 0x%" PRIx64 "\n", 
		msg_num,
		p_key_nonce->nonce_i,
		*(uint64_t*)&msg_nonce);
	unsigned long long clen;
	int enc_ret = crypto_aead_chacha20poly1305_encrypt(
		p_outbuf,
		&clen,
		p_inbuf,
		inbuf_len,
		NULL, 0, NULL,
		msg_nonce,
		p_key_nonce->key
		);
	if (enc_ret != 0) {
		logerror("crypto_aead_chacha20poly1305_encrypt returned non-zero\n");
		return -1;
	}
	assert(clen <= outbuf_len);
	loginfo("clen = %llu\n",clen);

	// Write to stdout
	ssize_t n_wrote = write(STDOUT_FILENO, &clen, sizeof clen);
	if (n_wrote != sizeof clen) {
		logerror("write() on block length prefix failed; errno = %d\n",errno);
		perror("ERROR: ");
		return -1;
	}
	n_wrote = write(STDOUT_FILENO, p_outbuf, clen);
	if (n_wrote != clen) {
		logerror("write() on full block failed; errno = %d\n",errno);
		perror("ERROR: ");
		return -1;
	}

	return 0;
}

int decrypt_msg_block_to_stdout(
		const key_nonce_t* const p_key_nonce, 
		const unsigned char* const p_inbuf, 
		size_t const inbuf_len,
		const uint64_t msg_num
) {
	size_t outbuf_len_max = inbuf_len;
	unsigned char * p_outbuf = (unsigned char *)malloc(
			outbuf_len_max);
	if (p_outbuf==NULL) {
		logerror("failed to allocate %zu bytes\n",
			outbuf_len_max);
		return -1;
	}

	logtrace("p_outbuf is %zu bytes; inbuf_len = %zu, " \
		"crypto_aead_chacha20poly1305_ABYTES = %u, sizeof inbuf_len = %zu\n",
		outbuf_len_max,
		inbuf_len,
		crypto_aead_chacha20poly1305_ABYTES,
		sizeof inbuf_len);
	size_t outbuf_len;
	unsigned char msg_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
	get_msg_nonce(p_key_nonce->nonce_s, msg_num, msg_nonce);
	loginfo("msg 0x%" PRIx64 ": initial nonce 0x%" PRIx64 ", curr nonce 0x%" PRIx64 "\n", 
		msg_num,
		p_key_nonce->nonce_i,
		*(uint64_t*)&msg_nonce);
	static_assert(sizeof(unsigned long long)==sizeof(size_t), 
		"Cast below requires these types to be same size");

	char* p_hex = (char*)malloc((inbuf_len*2)+1024);
	memset(p_hex, 0, (inbuf_len*2)+1024); 
	assert(p_hex!=NULL);
	sodium_bin2hex(p_hex, ((inbuf_len*2)+1024)-1, p_inbuf, inbuf_len);
	logtrace("p_inbuf before decryption = '%s'\n",p_hex);

	free(p_hex);
	int dec_ret = crypto_aead_chacha20poly1305_decrypt(
		p_outbuf,
		(unsigned long long*)&outbuf_len,
		NULL,
		p_inbuf+sizeof(uint64_t),
		inbuf_len-sizeof(uint64_t),
		NULL, 0,
		msg_nonce,
		p_key_nonce->key
		);
	if (dec_ret == -1) {
		logerror("authentication tag was rejected during decryption\n");
		return -1;
	} else if (dec_ret != 0) {
		logerror("crypto_aead_chacha20poly1305_decrypt returned non-zero\n");
		return -1;
	}
	assert(outbuf_len <= outbuf_len_max);

	// Write to stdout
	ssize_t n_wrote = write(STDOUT_FILENO, p_outbuf, outbuf_len);
	if (n_wrote != outbuf_len) {
		logerror("write() on full plaintext block failed; errno = %d\n",errno);
		perror("ERROR: ");
		return -1;
	}

	free(p_outbuf);

	return 0;
}

// Functions for determinisitic RNG (generates 0a's always)
const char * test_rng_all_0a_implementation_name(void) { return "test_rng_all_0a"; }
uint32_t test_rng_all_0a_random(void) { return 0x0a0a0a0a; }
uint32_t test_rng_all_0a_uniform(const uint32_t upper_bound) { return test_rng_all_0a_random() % upper_bound; }
void test_rng_all_0a_buf(void * const buf, const size_t size) { memset(buf, 0x0a, size); }


typedef struct {
	char mark[4];                 // "chch"
	uint32_t version;             // =1
	uint32_t block_size;          // in kb
	uint32_t _pad;                // zeros (to align next elem to 16-byte)
	unsigned char salt[SALT_LEN]; // 128-bit password salt
	uint64_t crypto_pwhash_opslimit;
	size_t crypto_pwhash_memlimit;
	// Some options for last two:
	//   Fastest:  crypto_pwhash_OPSLIMIT_INTERACTIVE , crypto_pwhash_MEMLIMIT_INTERACTIVE
	//   Most secure:  crypto_pwhash_OPSLIMIT_SENSITIVE , pwhash_MEMLIMIT_EXTREME
	//     (where:  const unsigned long long pwhash_MEMLIMIT_EXTREME = 4294967296ULL; )
} hdr_t;
static_assert(sizeof(hdr_t)==48, "Expecting packed header struct");

int main_decrypt(int argc, char** argv, char* const passbuf, size_t const passbuf_len) {
	ssize_t n_read;

	// Read and check ciphertext file header from stdin
	hdr_t hdr;
	n_read = read(STDIN_FILENO, &hdr, sizeof hdr);
	if (n_read < sizeof hdr) {
		logerror("could not read header from stdin\n");
		return -1;
	}
	// ^^^ TODO: this isn't really a fatal error, just an under-read
	if (
		(strncmp(hdr.mark, "chch", 4) != 0) ||
		(hdr.version != 1) ||
		(hdr._pad != 0)
	) {
		logerror("invalid input file (ciphertext header format)\n");
		return -1;
	}
	size_t block_size_bytes = hdr.block_size*1024;
	char hex[1024] = {'\0'};
	sodium_bin2hex(hex, sizeof(hex)-1, hdr.salt, sizeof(hdr.salt));
	loginfo("salt = '%s'\n",hex);
	
	// Derive key + nonce from passphrase & header (salt and hash params)
	key_nonce_t key_nonce;
	derive_key(passbuf, passbuf_len, hdr.salt, &key_nonce, sizeof key_nonce, 
			hdr.crypto_pwhash_opslimit, hdr.crypto_pwhash_memlimit);
	sodium_bin2hex(hex, sizeof(hex)-1, key_nonce.key, sizeof(key_nonce.key));
	loginfo("key buffer = '%s'\n",hex);
	sodium_bin2hex(hex, sizeof(hex)-1, key_nonce.nonce_s, sizeof(key_nonce.nonce_s));
	loginfo("nonce buffer = '%s'\n",hex);

	// Read in, decrypt and write out each block (first 8 bytes are size of block)
	char c;
	size_t pos = 0;
	uint64_t msg_num = 0;
	size_t inbuf_len = sizeof(unsigned long long)+crypto_aead_chacha20poly1305_ABYTES+
		block_size_bytes; // 8 + 16 + block_size_bytes
	unsigned char * p_inbuf = (unsigned char*) malloc(inbuf_len);
	size_t curr_block_len = 0;
	while ((n_read = read(STDIN_FILENO, &c, 1)) > 0) {
		p_inbuf[pos] = c;

		if (pos<sizeof(size_t)-1) {
			// loop until first sizeof(size_t) bytes available
		} else if (pos==sizeof(size_t)-1) {
			curr_block_len = *(size_t*)p_inbuf;
			logtrace("curr_block_len = %zu\n", curr_block_len);
		} else {
			// do we have entire block?
			if (pos==curr_block_len+sizeof(size_t)-1) {
				logtrace("calling decrypt_msg_block_to_stdout with inbuf_len=%zu\n",
					pos+1);
				decrypt_msg_block_to_stdout(&key_nonce, p_inbuf, pos+1, msg_num);
				
				// next iteration
				msg_num++;
				pos = 0;
				continue;
			}
		}

		pos++;
	}
	sodium_memzero(p_inbuf, inbuf_len);
	free(p_inbuf);

	return 0;
}

int main_encrypt(int argc, char** argv, char* const passbuf, size_t const passbuf_len) {
	// Prepare output file header including random passphrase salt and params
	hdr_t hdr = { 
		{'c','h','c','h'}, 
		(uint32_t)(1),
		MSG_BLOCK_LEN_KB,
		(uint32_t)(0),
		{'\0'},
		crypto_pwhash_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_MEMLIMIT_INTERACTIVE
	};
	randombytes_buf(hdr.salt, sizeof hdr.salt);
	char hex[1024] = {'\0'};
	sodium_bin2hex(hex, sizeof(hex)-1, hdr.salt, sizeof(hdr.salt));
	loginfo("salt = '%s'\n",hex);

	// Derive key and starting nonce from passphrase & salt
	key_nonce_t key_nonce = { {'\0'}, { {'\0'} } };
	derive_key(passbuf, passbuf_len, hdr.salt, &key_nonce, sizeof(key_nonce), 
			hdr.crypto_pwhash_opslimit, hdr.crypto_pwhash_memlimit);
	sodium_bin2hex(hex, sizeof(hex)-1, key_nonce.key, sizeof(key_nonce.key));
	loginfo("key buffer = '%s'\n",hex);
	sodium_bin2hex(hex, sizeof(hex)-1, key_nonce.nonce_s, sizeof(key_nonce.nonce_s));
	loginfo("nonce buffer = '%s'\n",hex);
	
	// Passphrase no longer needed
	sodium_memzero(passbuf, sizeof(passbuf));  //TODO:  guarded heap free

	// Prepend header to stdout
	ssize_t n_wrote = write(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (n_wrote != sizeof hdr) {
		logerror("write() failed; errno = %d\n",errno);
		perror("ERROR: ");
		return -1;
	}
	// TODO:  (n_wrote != sizeof hdr) is not necessarily an error
	
	// read stdin and encrypt each block (or final partial block)
	ssize_t bytes_read;
	char c;
	size_t pos = 0;
	uint64_t msg_num = 0;
	size_t block_size_bytes = hdr.block_size*1024;
	size_t outbuf_len = crypto_aead_chacha20poly1305_ABYTES+block_size_bytes; // 16 + block_size_bytes
	loginfo("outbuf_len = %zu, sizeof(unsigned long long) = %zu, crypto_aead_chacha20poly1305_ABYTES = %u, block_size_bytes = %zu\n",
		outbuf_len,
		sizeof(unsigned long long),
		crypto_aead_chacha20poly1305_ABYTES,
		block_size_bytes);
	unsigned char * p_inbuf = (unsigned char*) malloc(block_size_bytes);
	if (!p_inbuf) {
		logerror("malloc(%zu b) failed\n",block_size_bytes);
		return -1;
	}
	// TODO:  allocate/free p_outbuf inside the subroutine
	unsigned char * p_outbuf = (unsigned char*) malloc(outbuf_len);
	if (!p_outbuf) {
		logerror("malloc(%zu b) failed\n",outbuf_len);
		return -1;
	}
	while ((bytes_read = read(STDIN_FILENO, &c, 1)) > 0) {
		p_inbuf[pos++] = c;
		if (pos==block_size_bytes) {
			encrypt_msg_block_to_stdout(&key_nonce, p_inbuf, pos, p_outbuf, outbuf_len, msg_num);

			// next iteration
			msg_num++;
			pos = 0;
		}
	}

	// partial block?
	if (pos>0) {
		encrypt_msg_block_to_stdout(&key_nonce, p_inbuf, pos, p_outbuf, outbuf_len, msg_num);
		msg_num++;
	}

	sodium_memzero(p_inbuf, block_size_bytes);
	sodium_memzero(p_outbuf, outbuf_len);
	free(p_inbuf);
	free(p_outbuf);

	loginfo("ok\n");

	return 0;
}

static struct option long_options[] =
{
	{"verbose", no_argument,       NULL,  'v'},
	{"encrypt", no_argument,       NULL,  'e'},
	{"decrypt", no_argument,       NULL,  'd'},
	{"help",    no_argument,       NULL,  'h'},
	{"fake-rng",no_argument,       NULL,  0},
	{0, 0, 0, 0}
};

void usage(const char* const progname) {
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Use ChaCha20-Poly1305 to encrypt stdin to stdout. Passphrase is read from\n");
	fprintf(stderr, "the file \".passphrase\" in current directory.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  -e, --encrypt     Encrypt (default)\n");
	fprintf(stderr, "  -d, --decrypt     Decrypt\n");
	fprintf(stderr, "  -v, --verbose     Verbose output (may use twice)\n");
	fprintf(stderr, "  -h, --help        Print this message\n");
	fprintf(stderr, "  --fake-rng        Override system RNG with one that always generates\n" \
		        "                    byte strings 0a0a0a...  For testing only!\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Encrypt a file under passphrase \"12345\":\n");
	fprintf(stderr, "  echo \"12345\" > .passphrase ; %s -e < plaintext > ciphertext\n", progname);
	fprintf(stderr, "Decrypt back to original:\n");
	fprintf(stderr, "  %s -d ciphertext.bin\n",progname);
}

int main(int argc, char** argv) {
	int mode = 'e';
	bool b_use_deterministic_rng = false;

	// CLI options
	while (1) {
		int option_index = 0;
		int c = getopt_long (argc, argv, "edvh", long_options, &option_index);
		if (c==-1) break;
		switch (c) {
			case 0:
				if (optarg)
					loginfo("option '%s' with arg '%s'\n", long_options[option_index].name, optarg);
				else
					loginfo("option '%s'\n", long_options[option_index].name);
				if (strncmp(long_options[option_index].name, "fake-rng", sizeof("fake-rng"))) {
					b_use_deterministic_rng = true;
				}
				break;
			case 'v':
				loginfo("option 'v'\n");
				if (g_loglevel & LOG_TRACE)
					; // already at max verbosity
				else if (g_loglevel & LOG_INFO) 
					g_loglevel = (LOG_ERROR|LOG_WARN|LOG_INFO|LOG_TRACE);
				else if (g_loglevel & LOG_WARN) 
					g_loglevel = (LOG_ERROR|LOG_WARN|LOG_INFO);
				else if (g_loglevel & LOG_ERROR)
					g_loglevel = (LOG_ERROR|LOG_WARN);
				else
					g_loglevel = LOG_ERROR;
				break;
			case 'e':
				loginfo("option 'e'\n");
				mode = 'e';
				break;
			case 'd':
				loginfo("option 'd'\n");
				mode = 'd';
				break;
			case 'h':
				loginfo("option 'h'\n");
				usage(argv[0]);
				exit(0);
				break;
			default:
				fprintf(stderr, "Unrecognized option '%c'\n", c);
				usage(argv[0]);
				exit(1);
				break;
		}
	}

	// Set fake RNG before sodium_init
	if (b_use_deterministic_rng) {
		randombytes_implementation impl = {
			test_rng_all_0a_implementation_name,
			test_rng_all_0a_random,
			NULL,
			test_rng_all_0a_uniform,
			test_rng_all_0a_buf,
			NULL
		};
		int custom_rng_ret = randombytes_set_implementation(&impl);
		if (custom_rng_ret!=0) {
			logerror("failed to set deterministic rng\n");
			return -1;
		} else {
			logwarn("using deterministic random number generator (for testing only)\n");
		}
	}

	// Read in passphrase
	char passbuf[255] = {'\0'}; //TODO:  use guarded heap alloc
	size_t passbuf_len = 0;
	int rc = get_passphrase(passbuf,&passbuf_len,sizeof(passbuf));
	if (rc!=0) {
		logerror("get_passphrase() failed\n");
		return -1;
	} else {
		loginfo("passphrase '%s'\n",passbuf);
	}

	if ( sodium_init() == -1 ) {
		return 1;
	}

	// Encrypt or decrypt
	int ret;
	if (mode=='e') {
		ret = main_encrypt(argc,argv,passbuf,passbuf_len);
	} else {
		ret = main_decrypt(argc,argv,passbuf,passbuf_len);
	}
	return ret;
}

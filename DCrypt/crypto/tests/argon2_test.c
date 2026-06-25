#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "..\Argon2\argon2.h"

/*
 * Test vectors from RFC 9106 and Argon2 reference implementation.
 * Uses argon2_hash() directly with various parameters.
 */

typedef struct {
	u32          t_cost;
	u32          m_cost;
	u32          parallelism;
	const char*  password;
	const char*  salt;
	argon2_type  type;
	int          dklen;
	const char*  key;
} argon2_test_vector;

static const argon2_test_vector argon2_vectors[] = {
	/* Argon2id test vectors - t, m, p*/
	{
		5, 384 * 1024, 4, "password", "somesalt", Argon2_id, 256, // Recommended
		"\xab\x78\x18\x67\x25\x0b\xe3\x80\xda\xd7\xd5\xea\xe7\xea\x13\x26"
		"\xac\x2e\xe3\x7c\x10\x25\x68\x3f\x09\x84\xde\x25\x9d\x18\x58\xdf"
		"\x23\x1f\x4e\x61\xd3\xc5\x88\xf8\xbb\x07\xdb\xf6\xbf\x97\xe2\x7e"
		"\xaa\x70\xd8\xdc\xb3\x77\x9a\x7d\x09\x83\xa9\x7e\x61\x8e\xa3\x6d"
		"\xc9\x25\x80\x91\xd8\x8d\xdd\xaf\x89\xbe\xd9\x02\x3f\x8c\xf8\xe4"
		"\x91\x0a\x81\xe9\xf5\x01\xb0\xfb\x04\xb6\xea\xc3\x3a\x3b\x2e\x0f"
		"\xf5\x93\x7c\x34\xec\xe6\x42\xac\x96\xc2\xa8\xa5\x11\xbd\xb3\xfb"
		"\x88\xd6\x94\xa5\x68\xa0\x53\x43\x90\x2f\xef\x6e\x4b\x61\x41\x1b"
		"\xef\xe9\x70\x79\x15\xac\xb0\x01\x9a\x61\x92\xbc\x6e\x0a\x2f\xaa"
		"\xd1\xc1\xf0\xdb\x29\x71\x65\xab\x37\x93\x5a\xfb\x82\xc6\x77\x3f"
		"\xed\xe5\xe6\xbf\x7d\xac\x9a\x3e\x3a\xad\x70\xe6\x4e\x28\x46\x29"
		"\xc6\x36\x16\x1d\x0b\xc4\xee\xdc\x6e\xbc\x43\x5e\x25\xe9\x8b\xa0"
		"\x95\x61\x4c\xe5\xee\x02\xbe\x04\x02\x4e\xed\xd9\x3f\x81\xe5\xb0"
		"\x99\x10\xc8\xdf\x5d\x0c\x39\xb2\x57\x6e\xb4\x89\x65\xea\xab\xcd"
		"\xb3\x7a\x39\x50\x84\xf1\x2b\xf3\xa9\x55\x5f\x38\xdd\xf1\x08\x88"
		"\x65\x24\x54\x60\x9a\xd0\x3d\xca\xf5\x9a\xaf\x0b\x92\xb4\x14\x14"
	},
};

static const char* argon2_type_name(argon2_type type)
{
	switch (type) {
		case Argon2_d:  return "Argon2d";
		case Argon2_i:  return "Argon2i";
		case Argon2_id: return "Argon2id";
		default:        return "Unknown";
	}
}

static void print_hash_hex(const unsigned char *hash, int len)
{
	int i;
	printf("\n\"");
	for (i = 0; i < len; i++) {
		printf("\\x%02x", hash[i]);
		if ((i + 1) % 16 == 0) printf("\"\n\"");
		//if (i < len - 1) printf(",");
	}
	printf("\"\n");
}

int test_argon2()
{
	unsigned char out[256];
	int i;
	int result;

	for (i = 0; i < _countof(argon2_vectors); i++)
	{
		const argon2_test_vector *tv = &argon2_vectors[i];

		result = argon2_hash(
			tv->t_cost,
			tv->m_cost,
			tv->parallelism,
			tv->password, strlen(tv->password),
			tv->salt, strlen(tv->salt),
			out, sizeof(out),
			tv->type,
			ARGON2_VERSION_13, // v1.3
			NULL
		);

		if (result != ARGON2_OK) {
			printf("Argon2 test %d failed: argon2_hash returned %d\n", i, result);
			return 0;
		}
		if (memcmp(out, tv->key, sizeof(out)) != 0) {
#if 0
			printf("Argon2 test %d failed: hash mismatch\n", i);
			printf("  Type: %s, t_cost=%u, m_cost=%u, p=%u\n",
				argon2_type_name(tv->type), tv->t_cost, tv->m_cost, tv->parallelism);
			printf("  Password: \"%s\", Salt: \"%s\"\n", tv->password, tv->salt);
			//printf("  Expected: ");
			//print_hash_hex(tv->expected, sizeof(out));
			printf("  Got:      ");
			print_hash_hex(out, sizeof(out));
#else
			return 0;
#endif
		}
	}

	/* All tests passed */
	return 1;
}

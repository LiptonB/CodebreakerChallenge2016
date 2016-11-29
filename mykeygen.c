#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/evp.h>

void masterkey(unsigned int seed, uint32_t *keyout) {
  unsigned int digest_length;
  int i;
  int rep;

  srand(seed);
  for (i = 0; i < 8; i++) {
    keyout[i] = rand();
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  for (rep = 0x400; rep--; ) {
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, (void *)keyout, 8*sizeof(*keyout));
    EVP_DigestFinal_ex(ctx, (unsigned char *)keyout, &digest_length);
  }
  EVP_MD_CTX_destroy(ctx);
}


void devicekey(uint32_t *master_key, unsigned char *device_key) {
  uint32_t serial = 2045071702;
  size_t digest_length = 0;
  int i;

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  const EVP_MD *sha256 = EVP_sha256();
  EVP_PKEY *mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
      (unsigned char *)master_key, 8*sizeof(*master_key));
  EVP_DigestSignInit(ctx, NULL, sha256, NULL, mac_key);

  EVP_DigestSignUpdate(ctx, &serial, sizeof(serial));
  EVP_DigestSignFinal(ctx, device_key, &digest_length);
}

int main(int argc, char *argv[]) {
  unsigned int seed = 0x583d9efa;
  uint32_t master_key[8];
  unsigned char device_key[32];
  int i;

  masterkey(seed, master_key);
  devicekey(master_key, device_key);
  for (i = 0; i < 32; i++) {
    printf("%02x", device_key[i]);
  }
  printf("\n");
}

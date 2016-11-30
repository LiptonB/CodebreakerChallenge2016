#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

void masterkey(unsigned int seed, uint32_t *keyout, EVP_MD_CTX *ctx) {
  unsigned int digest_length;
  int i;
  int rep;

  srand(seed);
  for (i = 0; i < 8; i++) {
    keyout[i] = rand();
  }

  for (rep = 0x400; rep--; ) {
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, (void *)keyout, 8*sizeof(*keyout));
    EVP_DigestFinal_ex(ctx, (unsigned char *)keyout, &digest_length);
  }
}


void devicekey(uint32_t *master_key, unsigned char *device_key) {
  uint32_t serial = 1794377989;
  size_t digest_length = 0;
  int i;

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  const EVP_MD *sha256 = EVP_sha256();
  EVP_PKEY *mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
      (unsigned char *)master_key, 8*sizeof(*master_key));
  EVP_DigestSignInit(ctx, NULL, sha256, NULL, mac_key);

  EVP_DigestSignUpdate(ctx, &serial, sizeof(serial));
  EVP_DigestSignFinal(ctx, device_key, &digest_length);
  EVP_PKEY_free(mac_key);
  EVP_MD_CTX_destroy(ctx);
}

int main(int argc, char *argv[]) {
  unsigned int seed = 0x583d9efa;
  uint32_t master_key[8];
  unsigned char device_key[33];
  const unsigned char target_key[] = "\xba\x67\x42\xa5\xc1\x17\x68\xe9\x81\xe2\x3d\x31\x6c\x35\x91\x8c\x82\x8a\x52\x22\x68\xb5\x64\x91\x62\xdf\x98\x75\xb5\xc1\x7c\xf2";
  int i;
  FILE *fp;

  printf("Target: ");
  for (i = 0; i < strlen(target_key); i++) {
    printf("%02x", target_key[i]);
  }
  printf("\n");

  EVP_MD_CTX *hash_ctx = EVP_MD_CTX_create();

  /*
  masterkey(seed, master_key, ctx);
  for (i = 0; i < 8; i++) {
    printf("%08x", master_key[i]);
  }
  printf("\n");
  devicekey(master_key, device_key, ctx);
  for (i = 0; i < 32; i++) {
    printf("%02x", device_key[i]);
  }
  printf("\n");

  device_key[32] = 0;

  printf("strcmp: %d\n", strcmp(device_key, target_key));
  printf("strlen(device_key)=%d strlen(target_key)=%d\n",
      strlen(device_key), strlen(target_key));
  */

  for (; seed > 0; seed--) {
    if (seed % 10000 == 0) {
      printf("Seed: %d\n", seed);
    }

    masterkey(seed, master_key, hash_ctx);

    devicekey(master_key, device_key);

    device_key[32] = 0;
    if (!strcmp(device_key, target_key)) {
      printf("FOUND! Seed is %d\n", seed);
      fp = fopen("realmaster", "wb");
      fwrite(master_key, 1, sizeof(master_key), fp);
      fclose(fp);
      break;
    }
  }

  EVP_MD_CTX_destroy(hash_ctx);
}

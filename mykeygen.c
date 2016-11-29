#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/evp.h>

void masterkey() {
  uint32_t randomdata[8];
  unsigned int digest_length;
  int i;
  int rep;
  unsigned int seed = 0x583d917a;

  srand(seed);
  for (i = 0; i < 8; i++) {
    randomdata[i] = rand();
    printf("0x%x\n", randomdata[i]);
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  for (rep = 0x400; rep--; ) {
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &randomdata, sizeof(randomdata));
    EVP_DigestFinal_ex(ctx, (unsigned char *)randomdata, &digest_length);
  }

  for (i = 0; i < digest_length/sizeof(*randomdata); i++) {
    printf("%08x", randomdata[i]);
  }
  printf("\n");
}


void devicekey() {
  char master_key[32];
  uint32_t serial = 2045071702;
  char digest[32];
  size_t digest_length = 0;
  int i;

  FILE *f = fopen("keyout", "r");
  fread(master_key, 1, 32, f);
  fclose(f);
  printf("Key begins with 0x%02x and ends with 0x%02x\n", master_key[0], master_key[31]);

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  const EVP_MD *sha256 = EVP_sha256();
  EVP_PKEY *mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, master_key,
      sizeof(master_key));
  EVP_DigestSignInit(ctx, NULL, sha256, NULL, mac_key);

  EVP_DigestSignUpdate(ctx, &serial, sizeof(serial));
  EVP_DigestSignFinal(ctx, digest, &digest_length);

  printf("digest_length: %d\n", digest_length);
  for (i = 0; i < digest_length; i++) {
    printf("%02hhx", digest[i]);
  }
  printf("\n");
}

int main(int argc, char *argv[]) {
  masterkey();
  //devicekey();
}

#include "otp.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/net.h"
#include "../include/err.h"
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>

int otp_encrypt_message(unsigned char *key, int klen, unsigned char *input, int ilen,
    unsigned char *output, int *olen);

int otp_decrypt_message(unsigned char *key, int klen, unsigned char *input, int ilen, 
    unsigned char *output, int *olen);

// TODO: You should write down this function. You can modify the function as you want.
/* @brief the function that performs the OTP operation
 * @param key the pointer to the key
 * @param klen the length of the key
 * @param input the pointer to the input message
 * @param ilen the length of the input message
 * @param output the pointer to the output message
 * @param olen the length of the output message
 * @param op the operation (encryption / decryption)
 * @return SUCCESS/FAILURE
 */
int otp_operation(unsigned char *key, int klen, unsigned char *input, int ilen, 
    unsigned char *output, int *olen, int op)
{
  fstart("key: %p, klen: %d, input: %p, ilen: %d, output: %p, olen: %p, op: %d", 
      key, klen, input, ilen, output, olen, op);

  assert(input != NULL);
  assert(output != NULL);
  assert(ilen > 0);
  assert(klen >= ilen);
  assert(olen != NULL);

  // TODO: the length of the output message should be assigned to *olen
  // *olen = ;

  if (op == OTP_ENCRYPT)
    return otp_encrypt_message(key, klen, input, ilen, output, olen);
  else if (op == OTP_DECRYPT)
    return otp_decrypt_message(key, klen, input, ilen, output, olen);
  else
    return FAILURE;
}

// TODO: You should write down this function. You can modify the function as you want.
/* @brief the function that performs the OTP encryption
 * @param key the pointer to the key
 * @param klen the length of the key
 * @param input the pointer to the input message
 * @param ilen the length of the input message
 * @param output the pointer to the output message
 * @param olen the length of the output message
 * @return SUCCESS/FAILURE

 */
int otp_encrypt_message(unsigned char *key, int klen, unsigned char *input, int ilen,
    unsigned char *output, int *olen)
{
  fstart("key: %p, klen: %d, input: %p, ilen: %d, output: %p, olen: %p",
      key, klen, input, ilen, output, olen);

  // TODO: the length of the output message should be assigned to *olen
  // *olen = ;
  *olen = ilen;

  ffinish();
  return SUCCESS;
}

// TODO: You should write down this function. You can modify the function as you want.
/* @brief the function that performs the OTP decryption
 * @param key the pointer to the key
 * @param klen the length of the key
 * @param input the pointer to the input message
 * @param ilen the length of the input message
 * @param output the pointer to the output message
 * @param olen the length of the output message
 * @return SUCCESS/FAILURE
 */
int otp_decrypt_message(unsigned char *key, int klen, unsigned char *input, int ilen, 
    unsigned char *output, int *olen)
{
  fstart("key: %p, klen: %d, input: %p, ilen: %d, output: %p, olen: %p",
      key, klen, input, ilen, output, olen);

  // TODO: the length of the output message should be assigned to *olen
  // *olen = ;
  *olen = ilen;

  ffinish();
  return SUCCESS;
}

struct keystream *init_key_stream(const char *fname)
{
  fstart("fname: %p", fname);

  struct keystream *ret;
  FILE *fp;
  int klen;
  fp = NULL;

  if (fname)
  {
    fp = fopen(fname, "rb");
    if (!fp)
    {
      emsg("Open the file %s failed", fname);
      goto err;
    }
  }

  ret = (struct keystream *)malloc(sizeof(struct keystream));
  if (!ret)
  {
    emsg("Out of memory during a keystream malloc");
    goto err;
  }
  memset(ret, 0x0, sizeof(struct keystream));

  if (fp)
  {
    fseek(fp, 0L, SEEK_END);
    ret->max = ftell(fp);
    ret->key = (unsigned char *)malloc(ret->max);
    if (!(ret->key))
    {
      emsg("Out of memory during a key malloc");
      goto err;
    }

    fseek(fp, 0L, SEEK_SET);
    klen = fread(ret->key, 1, ret->max, fp);
    if (klen != ret->max)
    {
      emsg("Read key file error");
      goto err;
    }
  }

  return ret;
err:
  if (ret)
  {
    if (ret->key)
    {
      free(ret->key);
      ret->key = NULL;
    }
    free(ret);
    ret = NULL;
  }
  return NULL;
}

void free_key_stream(struct keystream *kst)
{
  fstart("kst: %p", kst);

  if (kst)
  {
    if (kst->key)
    {
      free(kst->key);
      kst->key = NULL;
    }
    kst->idx = -1;
    kst->max = -1;
    free(kst);
    kst = NULL;
  }

  ffinish("kst: %p", kst);
}

int send_otp_key_bytes(int fd, struct keystream *kst)
{
  fstart("fd: %d, kst: %p", fd, kst);
  int ret, klen;
  unsigned char key[MAX_KEY_LENGTH] = {0, };

  assert(fd > 0);
  assert(kst != NULL);
  assert(kst->key != NULL);
  assert(kst->max > 0);

  klen = kst->max;
  memcpy(key, kst->key, klen);

  ret = send_message(fd, key, klen);

  dprint("Sent OTP key bytes", key, 0, klen, 10);

  ffinish("ret: %d", ret);
  return ret;
}

int receive_otp_key_bytes(int fd, struct keystream *kst)
{
  fstart("fd: %d, kst: %p", fd, kst);
  int ret;

  assert(fd > 0);
  assert(kst != NULL);
  
  if (!(kst->key))
  {
    kst->key = (unsigned char *)malloc(MAX_KEY_LENGTH);
    memset(kst->key, 0x0, MAX_KEY_LENGTH);
  }
  ret = receive_message(fd, kst->key, MAX_KEY_LENGTH);
  kst->max = ret;

  dprint("Received OTP key bytes", kst->key, 0, kst->max, 10);

  ffinish("ret: %d", ret);
  return ret;
}

int get_otp_key_bytes(struct keystream *kst, unsigned char *key, int bytes)
{
  fstart("kst: %p, key: %p, bytes: %d", kst, key, bytes);

  int ret;

  assert(kst != NULL);
  assert(key != NULL);
  assert(bytes <= BUF_SIZE);
  assert(kst->idx + bytes <= kst->max);

  memcpy(key, kst->key + kst->idx, bytes);
  kst->idx += bytes;
  ret = bytes;

  ffinish("ret: %d", ret);
  return ret;
}

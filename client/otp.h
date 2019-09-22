#ifndef __OTP_H__
#define __OTP_H__

#define OTP_ENCRYPT 1
#define OTP_DECRYPT 2

#include <stdio.h>
#include <time.h>

struct keystream
{
  unsigned char *key;
  int idx;
  int max;
};

struct keystream *init_key_stream(const char *fname);
void free_key_stream(struct keystream *kst);

int send_otp_key_bytes(int fd, struct keystream *kst);
int receive_otp_key_bytes(int fd, struct keystream *kst);
int get_otp_key_bytes(struct keystream *stream, unsigned char *key, int bytes);
int otp_operation(unsigned char *key, int klen, unsigned char *input, int ilen, 
    unsigned char *output, int *olen, int op);

#endif /* __OTP_H__ */

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <pthread.h>

#include "otp.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/setting.h"
#include "../include/conn.h"
#include "../include/http.h"
#include "../include/net.h"
#include "../include/err.h"

int usage(const char *pname)
{
  emsg(">> usage: %s -h <domain> -p <portnum> -k <key file>", pname);
  emsg(">> example: %s -h www.alice.com -p 5555 -k ../key/otp-key.txt", pname);
  exit(0);
}

// Client Prototype Implementation
int main(int argc, char *argv[])
{   
  const char *domain, *keyfile, *pname;
	int port, server;
  struct keystream *kst;
  unsigned char buf[BUF_SIZE] = {0, };
  unsigned char key[BUF_SIZE] = {0, };
  unsigned char plain[BUF_SIZE] = {0, };
  unsigned char ciph[BUF_SIZE] = {0, };
  const char *start = "Start";
  int ret, clen, rlen, plen, klen, c, err;

  pname = argv[0];
  domain = NULL;
  port = -1;
  keyfile = NULL;
  err = 0;

  /* Get command line arguments */
  while ((c = getopt(argc, argv, "h:p:k:")) != -1)
  {
    switch (c)
    {
      case 'h':
        domain = optarg;
        imsg("Domain: %s", domain);
        break;
      case 'p':
        port = atoi(optarg);
        imsg("Port: %d", port);
        break;
      case 'k':
        keyfile = optarg;
        imsg("Key File Path: %s", keyfile);
        break;
      default:
        usage(pname);
    }
  }

  /* Handle errors */
  if (!domain)
  {
    err |= ERR_DOMAIN_NAME;
  }
  
  if (port < 0)
  {
    err |= ERR_PORT_NUMBER;
  }

  if (!keyfile)
  {
    err |= ERR_KEY_FILE;
  }

  if (err)
  {
    emsg("Error in arguments");
    if (err & ERR_DOMAIN_NAME)
      emsg("Please insert the domain name (or IP address) of the server with the '-h' flag.");

    if (err & ERR_PORT_NUMBER)
      emsg("Please insert the port number of the server with the '-p' flag.");

    if (err & ERR_KEY_FILE)
      emsg("Please insert the path of the key file with the '-k' flag.");

    usage(pname);
  }

  /* Initialize the keystream */
  kst = init_key_stream(keyfile);
  if (!kst)
  {
    emsg("Initialize the key stream failed");
    abort();
  }

  /* Set the TCP connection with the server */
	server = open_connection(domain, port);
  if (server <= 2)
  {
    emsg("Open TCP connection failed");
    abort();
  }

  /* Send the OTP key bytes to Server */
  ret = send_otp_key_bytes(server, kst);
  if (ret == FAILURE)
  {
    emsg("Send the key bytes failed");
    abort();
  }

  /* Get the one-time-pad encryption key for the start message */
  ret = get_otp_key_bytes(kst, key, strlen(start));
  if (ret == FAILURE)
  {
    emsg("Get the OTP key failed: %lu bytes", strlen(start));
    abort();
  }
  klen = ret;

  /* TODO: OTP-encrypt the start message */
  ret = otp_operation(key, klen, start, strlen(start), ciph, &clen, OTP_ENCRYPT);
  if (ret == FAILURE)
  {
    emsg("Encrypt the start message failed");
    abort();
  }

  /* Send the start message to Server */
  ret = send_message(server, ciph, clen);
  if (ret == FAILURE)
  {
    emsg("Send the start message failed");
    abort();
  }

  imsg("Sent message (%lu bytes): %s", strlen(start), start);
  dprint("Encryption Key", key, 0, klen, 10);
  iprint("Ciphertext", ciph, 0, clen, 10);

  /* Receive the challenge message from Server */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the challenge message failed");
    abort();
  }
  rlen = ret;
  
  /* Get the one-time-pad decryption key for the challenge message */
  ret = get_otp_key_bytes(kst, key, rlen);
  if (ret == FAILURE)
  {
    emsg("Get the OTP key failed: %d bytes", rlen);
    abort();
  }
  klen = ret;

  /* TODO: Decrypt the challenge message */
  ret = otp_operation(key, klen, buf, rlen, plain, &plen, OTP_DECRYPT);
  if (ret == FAILURE)
  {
    emsg("Decrypt the challenge message failed");
    abort();
  }

  iprint("Received message", buf, 0, rlen, 10);
  dprint("Encryption key", key, 0, klen, 10);
  imsg("Challenge (%d bytes): %s", plen, plain);

  free_key_stream(kst);

	return 0;
}

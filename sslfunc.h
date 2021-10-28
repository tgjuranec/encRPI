/*
 * sslfunc.h
 *
 *  Created on: Sep 3, 2021
 *      Author: linuser
 */

#ifndef SSLFUNC_H_
#define SSLFUNC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int encrypt(const char *plainFile, const char * keyfile, const char *encFile);

int decrypt(const char *encFile, const char * keyfile, const char *decfile);

int signFile(const char *plainFile, const char * keyfile, const char *signature);

/*
 * returns 1 if verification is successful.
 *
 */
int verifyFile(const char *plainFile, const char * keyfile, const char *signatureFile);

#ifdef __cplusplus
}
#endif

#endif /* SSLFUNC_H_ */

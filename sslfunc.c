/*
 * sslfunc.c
 *
 *  Created on: Sep 3, 2021
 *      Author: linuser
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "sslfunc.h"

#define MAX_THREADS 16



const int padding = RSA_PKCS1_OAEP_PADDING;

struct procdata{
	int order;
	unsigned char *input;
	int inputLen;
	unsigned char *output;
	int outputLen;
	RSA *rsa;
	int encpadding;
	unsigned long errorTrack;
};


static void *privateDecryptionThread(void *vargp){
	struct procdata *data = (struct procdata *) vargp;

	int result = RSA_private_decrypt(data->inputLen,data->input,data->output,data->rsa,data->encpadding);
    if(result == -1){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
    }
    data->outputLen = result;
	return NULL;
}


static void *publicEncryptionThread(void *vargp){
	struct procdata *data = (struct procdata *) vargp;

	int result = RSA_public_encrypt(data->inputLen,data->input,data->output,data->rsa,data->encpadding);
    if(result == -1){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
    }
    data->outputLen = result;
	return NULL;
}




static RSA * createRSAWithFilename(const char * filename,int public)
{
    FILE * fp = fopen(filename,"rb");

    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;
    }
    RSA *rsa= RSA_new() ;

    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
    //GET KEY SIZE
    if(rsa == NULL){
    	return NULL;
    }
    return rsa;
}



int signFile(const char *plainFile, const char * keyfile, const char *signatureFile){
	unsigned char * plainData;	//buffer for plainFile
	unsigned char *bufSignature;//buffer for signature
	unsigned char *xorData;
	//INIT SSL VARIABLE
	RSA * rsa = createRSAWithFilename(keyfile,0);
	if(rsa == NULL){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
		return -1;
	}
	//OPEN PLAIN FILE
	FILE * fpPlainFile = fopen(plainFile,"rb");
	if(fpPlainFile == NULL){
		//TODO: handle this error
		return -1;
	}
    //OUTPUT FILE
    FILE * fpSignatureFile = fopen(signatureFile, "w");
    if(fpSignatureFile == NULL){
    	//TODO: handle this error
    	return -1;
    }
	//ALLOCATE
	int keySize = RSA_size(rsa);
	int chunkSize=keySize-42;
	plainData = malloc(chunkSize);
	xorData = malloc(chunkSize);
	memset(xorData,0,chunkSize);
	bufSignature = malloc(keySize);

	if(plainData == NULL){
		return -1;
	}
	unsigned int signatureLen;
	size_t readBytes;
	while((readBytes = fread(plainData,1,chunkSize,fpPlainFile)) > 0){
		for(int i = 0; i < readBytes; i++){
			xorData[i] ^= plainData[i];
		}
	}

	int result = RSA_sign(NID_sha256, xorData,(unsigned int) chunkSize, bufSignature, &signatureLen, rsa);
    if(result != 1){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
    	return -1;
    }

    size_t writtenBytes = fwrite(bufSignature,1,signatureLen,fpSignatureFile);
    if(writtenBytes != keySize){
    	printf("Error in write file: %s\n", signatureFile);
    	fclose(fpSignatureFile);
    	if(remove(signatureFile) == 0){
    		printf("File deleted\n");
    	}
    	else{
    		printf("File cannot be deleted, please remove it manually!\n");
    	}
    	return -1;
    }
    free(bufSignature);
    free(xorData);
    free(plainData);
    fclose(fpSignatureFile);
    fclose(fpPlainFile);
    RSA_free(rsa);
	return (int) signatureLen;
}

int verifyFile(const char *plainFile, const char * keyfile, const char *signatureFile){
	unsigned char * plainData;	//buffer for plainFile
	unsigned char *bufSignature;//buffer for signature
	unsigned char *xorData;
	//INIT SSL VARIABLE
	RSA * rsa = createRSAWithFilename(keyfile,1);
	if(rsa == NULL){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
		return -1;
	}
	//OPEN PLAIN FILE
	FILE * fpPlainFile = fopen(plainFile,"rb");
	if(fpPlainFile == NULL){
		return -1;
	}
	FILE * fpSignatureFile = fopen(signatureFile, "rb");
    if(fpSignatureFile == NULL){
    	return -1;
    }

	//ALLOCATE
	int keySize = RSA_size(rsa);
	int chunkSize=keySize-42;
	plainData = malloc(chunkSize);
	xorData = malloc(chunkSize);
	memset(xorData,0,chunkSize);
	bufSignature = malloc(keySize);
	if(plainData == NULL){
		return -1;
	}

	size_t readBytes;
	readBytes = fread(bufSignature,1,keySize,fpSignatureFile);
	while((readBytes = fread(plainData,1,chunkSize,fpPlainFile)) > 0){
		for(int i = 0; i < readBytes; i++){
			xorData[i] ^= plainData[i];
		}
	}

	int result = RSA_verify(NID_sha256, xorData, chunkSize, bufSignature, keySize, rsa);

    if(result != 1){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
    	return -1;
    }

    free(bufSignature);
    free(xorData);
    free(plainData);
    fclose(fpPlainFile);
    fclose(fpSignatureFile);
    RSA_free(rsa);
	return result;
}

int encrypt(const char *plainFile, const char * keyfile, const char *encFile)
{
	unsigned char * data;	//buffer for plainFile
	unsigned char *encrypted;//buffer for encFile
	//OPEN PLAIN FILE
	FILE * fpPlainFile = fopen(plainFile,"rb");
    //OUTPUT FILE
    FILE * fpEncryptedFile = fopen(encFile, "w");

	//GET NUM OF CORES & allocate args
	int numCPU = sysconf(_SC_NPROCESSORS_ONLN);

	//INIT SSL VARIABLE
	RSA * rsa = createRSAWithFilename(keyfile,1);
	if(rsa == NULL){
    	unsigned long errorTrack = ERR_get_error();
    	printf("Error: %lu - %x\n", errorTrack, (unsigned int) errorTrack);
		return -1;
	}
    int keySize = RSA_size(rsa);
    int chunkSize=keySize-42;

	//ALLOCATE DATA BUFFERS
	data = malloc(chunkSize*numCPU);
	encrypted = malloc(keySize*numCPU);
	if(data == NULL || encrypted == NULL ){
		return -1;
	}

	//ALLOCATE THREAD PROCESS DATA
	struct procdata *pEncData = malloc(numCPU * sizeof(struct procdata));
	if(pEncData == NULL){
		return -1;
	}

	//THREAD TRACKING VARIABLES
	int orderCreated = 0, orderWritten = 0;

	//FILE TRACKING VARIABLES
	size_t readBytes, writtenBytes, writtenSum = 0;

	while((readBytes = fread(data,1,numCPU*(chunkSize),fpPlainFile)) > 0){
		//Number of needed threads depends on:
		// - number of available cores
		// - available data from the file
		int numthreads =  (((readBytes%chunkSize) > 0) ? 1 : 0) + readBytes/chunkSize;
		if(numthreads > MAX_THREADS){
			numthreads = MAX_THREADS;
		}
		pthread_t thread_id[MAX_THREADS];
		int bytes_rest=readBytes;

		for(int i = 0; i < numthreads; i++){
			int dataSize = (bytes_rest > chunkSize) ? chunkSize : bytes_rest;
			bytes_rest -= dataSize;
			pEncData[i].encpadding = padding;
			pEncData[i].input = &data[i*chunkSize];
			pEncData[i].inputLen = dataSize;
			pEncData[i].output = &encrypted[i*keySize];
			pEncData[i].outputLen = -1;
			pEncData[i].rsa = rsa;
			pEncData[i].order = orderCreated;
			orderCreated++;
			pthread_create(&thread_id[i], NULL, publicEncryptionThread,(void *) &pEncData[i]);

		}
		for(int i = 0; i < numthreads; i++){
			pthread_join(thread_id[i], NULL);
			if(pEncData[i].order == orderWritten){
				writtenBytes = fwrite(pEncData[i].output,1,pEncData[i].outputLen,fpEncryptedFile);
				writtenSum += writtenBytes;
				orderWritten++;
			}
			else{
				printf("Error in order thread. Expected:%d, presented: %d\n",orderWritten,pEncData[i].order);
				writtenSum = -1;
				goto encrypt_exit;
			}
		}
	}
	encrypt_exit:
	fclose(fpPlainFile);
    fclose(fpEncryptedFile);
    free(data);
    free(encrypted);
    free(pEncData);
    RSA_free(rsa);
    return writtenSum;
}



int decrypt(const char *encFile, const char * keyfile,const char *decfile)
{
	unsigned char * enc_data; //buffer for encFile
	unsigned char *decrypted; //buffer for decFile

	//OPEN ENCRYPTED FILE
	FILE * fpEncryptedFile = fopen(encFile,"rb");
	//OUTPUT FILE
	FILE * fpDecryptedFile = fopen(decfile, "w");

	//GET NUM OF CORES & allocate args
	int numCPU = sysconf(_SC_NPROCESSORS_ONLN);

	//INIT SSL variable
	RSA * rsa = createRSAWithFilename(keyfile,0);
	if(rsa == NULL){
		return -1;
	}
    int keySize = RSA_size(rsa);

	//ALLOCATE DATA BUFFERS
	enc_data = malloc(numCPU*keySize);
	decrypted = malloc(numCPU*keySize);
	if(enc_data == NULL || decrypted == NULL ){
		return -1;
	}

	//ALLOCATE THREAD PROCESS DATA
	struct procdata *pDecData = malloc(numCPU*sizeof(struct procdata));
	if(pDecData == NULL){
		return -1;
	}
	//THREAD TRACKING VARIABLES
	int orderCreated = 0, orderWritten = 0;

	//FILE TRACKING VARIABLES
	size_t readBytes, writtenBytes, writtenSum = 0;

	while((readBytes = fread(enc_data,1,numCPU*keySize,fpEncryptedFile)) > 0){
		//Number of needed threads depends on:
		// - number of available cores
		// - available data from the file
		//
		int numthreads =  (((readBytes%keySize) > 0) ? 1 : 0) + readBytes/keySize;
		if(numthreads > MAX_THREADS){
			numthreads = MAX_THREADS;
		}
		pthread_t thread_id[MAX_THREADS];
		int bytes_rest=readBytes;

		for(int i = 0; i < numthreads; i++){
			int dataSize = (bytes_rest > keySize) ? keySize : bytes_rest;
			bytes_rest -= dataSize;
			pDecData[i].encpadding = padding;
			pDecData[i].input = &enc_data[i*keySize];
			pDecData[i].inputLen = dataSize;
			pDecData[i].output = &decrypted[i*keySize];
			pDecData[i].rsa = rsa;
			pDecData[i].order = orderCreated;
			pDecData[i].outputLen = -1;
			orderCreated++;
			pthread_create(&thread_id[i], NULL, privateDecryptionThread,(void *) &pDecData[i]);

		}
		for(int i = 0; i < numthreads; i++){
			pthread_join(thread_id[i], NULL);
			if(pDecData[i].order == orderWritten){
				writtenBytes = fwrite(pDecData[i].output,1,pDecData[i].outputLen,fpDecryptedFile);
				writtenSum += writtenBytes;
				orderWritten++;
			}
			else{
				printf("Error in order thread. Expected:%d, presented: %d\n",orderWritten,pDecData[i].order);
				writtenSum = -1;
				goto decrypt_exit;
			}

		}
	}
	decrypt_exit:
	fclose(fpEncryptedFile);
	fclose(fpDecryptedFile);

	free(pDecData);
    free(enc_data);
    free(decrypted);
    RSA_free(rsa);
    return writtenSum;
}

#ifdef __cplusplus
}
#endif

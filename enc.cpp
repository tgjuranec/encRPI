//============================================================================
// Name        : enc.cpp
// Author      : tgjuranec
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <fstream>
#include <string.h>
#include <cstdio>
#include "sslfunc.h"



const char *optPrivateKey = "-k";
const char *optPublicKey = "-k";

const char *optActionEncrypt = "-e";
const char *optActionDecrypt = "-d";
const char *optActionSign = "-s";
const char *optActionVerify = "-v";

void printUsage(std::string files){
	std::cout  << "Usage: enc -k key -e|-d|-v|-s " << files << std::endl;
}

int main(int argc, char **argv) {
	char * inputFileName = NULL;
	char * outputFileName = NULL;

	//OUTPUT FILE NAME PROVIDED
	if(argc == 6 ){
		inputFileName = argv[4];
		size_t inputFileNameLen = strlen(argv[5]);
		outputFileName = new char[ inputFileNameLen + 1];
		strncpy(outputFileName, argv[5], inputFileNameLen);
		outputFileName[inputFileNameLen] = 0;
	}

	//OUTPUT FILE NAME NOT PROVIDED
	else if (argc == 5){
		inputFileName = argv[4];
		size_t processFileNameLen = strlen(argv[4]);
		outputFileName = new char[ processFileNameLen + 5];
		strncpy(outputFileName, argv[4], processFileNameLen);
		strncpy(&outputFileName[processFileNameLen], ".res", 5);
		outputFileName[processFileNameLen + 4] = 0;
	}
	//WRONG INPUT -> OUTPUT
	else {
		printUsage("inputfile [outputfile|signaturefile]");
		return 1;
	}

	//CHECK KEY
	char *privateKeyFile = nullptr;
	char *publicKeyFile = nullptr;

	//ENCRYPT WITH PUBLIC KEY -> ENCRYPTION
	if(strcmp(argv[3], "-e") == 0){
		int encrypted_length;
		if (strncmp(argv[1],optPublicKey,2) == 0){
			publicKeyFile = argv[2];
			encrypted_length= encrypt(inputFileName, publicKeyFile,outputFileName);
		}
		else {
			printUsage("inputfile [outputfile]");
			return 1;
		}
		std::cout << "Encrypted file: " << outputFileName << ", size: " << encrypted_length << std::endl;
	}
	//DECRYPT WITH PRIVATE KEY -> DECRYPTION
	else if(strcmp(argv[3], "-d") == 0){
		int decrypted_length;
		if(strncmp(argv[1],optPrivateKey,2) == 0){
			privateKeyFile = argv[2];
			decrypted_length= decrypt(inputFileName, privateKeyFile,outputFileName);
		}
		else {
			printUsage("inputfile [outputfile]");
			return 1;
		}
		std::cout << "Decrypted file: " << outputFileName << ", size: " << decrypted_length << std::endl;
	}
	//DIGITAL SIGNING
	else if(strcmp(argv[3], "-s") == 0){
		int signatureLen;
		if(strncmp(argv[1],optPrivateKey,2) == 0){
			privateKeyFile = argv[2];
			signatureLen= signFile(inputFileName, privateKeyFile, outputFileName);
		}
		else {
			printUsage("inputfile signaturefile");
			return 1;
		}
		std::cout << "Signature file: " << outputFileName << ", size: " << signatureLen << std::endl;
	}
	//DIGITAL SIGNATURE VERIFICATION
	else if(strcmp(argv[3], "-v") == 0){
		int verifiedFlag;
		if (strncmp(argv[1],optPublicKey,2) == 0){
			publicKeyFile = argv[2];
			verifiedFlag= verifyFile(inputFileName, publicKeyFile, outputFileName);
			if(verifiedFlag == 1){
				std::cout << "File: " << inputFileName << " VERIFIED SUCCESSFULLY!" << std::endl;
			}
			else{
				std::cout << "File: " << inputFileName << " NOT VERIFIED!" << std::endl;
			}
		}
		else {
			printUsage("inputfile signaturefile");
			return 1;
		}
	}
	else{
		printUsage("inputfile [outputfile|signaturefile]");
		return 1;
	}
	delete outputFileName;

	return 0;
}

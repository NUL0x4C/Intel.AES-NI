#pragma once


#include <Windows.h>

#ifndef AES_INTRINSIC_H
#define AES_INTRINSIC_H


void Aes256CBCEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes (must be a multiple of 16)
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);



void Aes256CBCDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes (must be a multiple of 16)
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv,					// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128CBCEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes (must be a multiple of 16)
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes128CBCDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes (must be a multiple of 16)
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv,					// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes256ECBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes (must be a multiple of 16)
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);

void Aes256ECBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes (must be a multiple of 16)
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 32 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128ECBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes (must be a multiple of 16)
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes128ECBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes (must be a multiple of 16)
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes256CFBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);

void Aes256CFBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128CFBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes128CFBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv,					// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes256CTREncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);

void Aes256CTRDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128CTREncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes128CTRDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes256GCMEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the buffer where the authentication tag will be stored (must be at least 16 bytes long)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);

void Aes256GCMDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the authentication tag (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128GCMEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the buffer where the authentication tag will be stored (must be at least 16 bytes long)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);

void Aes128GCMDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the authentication tag (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



void Aes256OCBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the buffer where the authentication tag will be stored (must be at least 16 bytes long)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes256OCBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the authentication tag (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128OCBEncrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes 
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the buffer where the authentication tag will be stored (must be at least 16 bytes long)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


void Aes128OCBDecrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes 
	IN		unsigned char*			pPlainText,				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 16 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 12 bytes)
	IN		unsigned char*			pAuthTag,				// Pointer to the authentication tag (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



#endif // !AES_INTRINSIC_H

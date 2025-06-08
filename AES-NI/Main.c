#include <Windows.h>
#include <stdio.h>



#include "Aes.intrinsic.h"



static const unsigned char	g_PlainText[]	=	"\tThis is a test of AES encryption using AES-NI intrinsics.\n"
							"\tThe (V)PSRLW instruction shifts each of the words in the destination operand to the right by the number of bits.\n"
							"\tspecified in the count operand; the(V)PSRLD instruction shifts each of the doublewords in the destination operand.\n"
							"\tand the PSRLQ instruction shifts the quadword(or quadwords) in the destination operand.\n"
							"\tVol. 2B 4-459\n";

static unsigned char		g_AesKey[]		= {
	0x01, 0x57, 0xBB, 0xC8, 0x8F, 0x49, 0x1E, 0x6A, 0x6A, 0xA5, 0xF9, 0x8C, 0x11, 0x40, 0x19, 0x2D,
	0x72, 0x38, 0x40, 0x35, 0xEE, 0xFA, 0x21, 0xCA, 0x92, 0x85, 0x4D, 0xA1, 0x25, 0xF1, 0x5C, 0x2E
};

static unsigned char		g_AesIv[]		= {
	0x3C, 0xB1, 0xE0, 0x1E, 0x70, 0x2B, 0x0C, 0xCE, 0x24, 0xB2, 0x89, 0x70, 0xF2, 0x2B, 0x43, 0x99
};

// Used With AEAD Algorithms Only
static unsigned char		g_AesNonce[] = {
    0x3C, 0xB1, 0xE0, 0x1E, 0x70, 0x2B, 0x0C, 0xCE, 0x24, 0xB2, 0x89, 0x70
};


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#define TEST_HEADER_256(ALG) printf("\n=== Testing AES-256 %s ===\n", ALG)
#define TEST_HEADER_128(ALG) printf("\n=== Testing AES-128 %s ===\n", ALG)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



int TestAes256CBC() { 

    TEST_HEADER_256("CBC");

    unsigned __int64  uPlainTextSize	= (strlen((char*)g_PlainText) + 15) & ~(size_t)0x0F;
    unsigned char*    pPaddedPlainText  = NULL;
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pPaddedPlainText = malloc(uPlainTextSize))) return -1;
    if (!(pCipherText      = malloc(uPlainTextSize))) { free(pPaddedPlainText); return -1; }
    if (!(pPlainText       = malloc(uPlainTextSize))) { free(pPaddedPlainText); free(pCipherText); return -1; }

    memset(pPaddedPlainText, 0, uPlainTextSize);
    memcpy(pPaddedPlainText, g_PlainText, strlen((char*)g_PlainText));

    Aes256CBCEncrypt(pPaddedPlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[CBC] Encryption successful\n");

    Aes256CBCDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[CBC] Decryption successful: %s\n", pPlainText);

    free(pPaddedPlainText);
    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes256ECB() {

    TEST_HEADER_256("EBC");

    unsigned __int64  uPlainTextSize	= (strlen((char*)g_PlainText) + 15) & ~(size_t)0x0F;
    unsigned char*    pPaddedPlainText  = NULL;
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pPaddedPlainText = malloc(uPlainTextSize))) return -1;
    if (!(pCipherText      = malloc(uPlainTextSize))) { free(pPaddedPlainText); return -1; }
    if (!(pPlainText       = malloc(uPlainTextSize))) { free(pPaddedPlainText); free(pCipherText); return -1; }

    memset(pPaddedPlainText, 0, uPlainTextSize);
    memcpy(pPaddedPlainText, g_PlainText, strlen((char*)g_PlainText));

    Aes256ECBEncrypt(pPaddedPlainText, uPlainTextSize, pCipherText, g_AesKey, &bEncrypted);
    if (!bEncrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[ECB] Encryption successful\n");

    Aes256ECBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, &bDecrypted);
    if (!bDecrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[ECB] Decryption successful: %s\n", pPlainText);

    free(pPaddedPlainText);
    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes256CFB() {

    TEST_HEADER_256("CFB");

    unsigned __int64  uPlainTextSize    = strlen((char*)g_PlainText);
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes256CFBEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CFB] Encryption successful\n");

    Aes256CFBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CFB] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}



int TestAes256CTR() {

    TEST_HEADER_256("CTR");

    unsigned __int64  uPlainTextSize   = strlen((char*)g_PlainText);
    unsigned char*    pCipherText      = NULL;
    unsigned char*    pPlainText       = NULL;
    unsigned char     bEncrypted       = FALSE;
    unsigned char     bDecrypted       = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes256CTREncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CTR] Encryption successful\n");

    Aes256CTRDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CTR] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes256GCM() {

    TEST_HEADER_256("GCM");

    unsigned __int64  uPlainTextSize    = strlen((char*)g_PlainText);
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     u8Tag[16]         = { 0 };
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes256GCMEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesNonce, u8Tag, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[GCM] Encryption successful\n");

    Aes256GCMDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesNonce, u8Tag, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[GCM] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes256OCB() {
    
    TEST_HEADER_256("OCB");

    unsigned __int64  uPlainTextSize    = strlen((char*)g_PlainText);
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     u8Tag[16]         = { 0 };
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes256OCBEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesNonce, u8Tag, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[OCB] Encryption successful\n");

    Aes256OCBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesNonce, u8Tag, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[OCB] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



int TestAes128CBC() { 

    TEST_HEADER_128("CBC");
     
    unsigned __int64  uPlainTextSize    = (strlen((char*)g_PlainText) + 15) & ~(size_t)0x0F;
    unsigned char*    pPaddedPlainText  = NULL;
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pPaddedPlainText = malloc(uPlainTextSize))) return -1;
    if (!(pCipherText      = malloc(uPlainTextSize))) { free(pPaddedPlainText); return -1; }
    if (!(pPlainText       = malloc(uPlainTextSize))) { free(pPaddedPlainText); free(pCipherText); return -1; }

    memset(pPaddedPlainText, 0, uPlainTextSize);
    memcpy(pPaddedPlainText, g_PlainText, strlen((char*)g_PlainText));

    Aes128CBCEncrypt(pPaddedPlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[CBC] Encryption successful\n");

    Aes128CBCDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[CBC] Decryption successful: %s\n", pPlainText);

    free(pPaddedPlainText);
    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes128ECB() { 

    TEST_HEADER_128("ECB");

    unsigned __int64  uPlainTextSize    = (strlen((char*)g_PlainText) + 15) & ~(size_t)0x0F;
    unsigned char*    pPaddedPlainText  = NULL;
    unsigned char*    pCipherText       = NULL;
    unsigned char*    pPlainText        = NULL;
    unsigned char     bEncrypted        = FALSE;
    unsigned char     bDecrypted        = FALSE;

    if (!(pPaddedPlainText = malloc(uPlainTextSize))) return -1;
    if (!(pCipherText      = malloc(uPlainTextSize))) { free(pPaddedPlainText); return -1; }
    if (!(pPlainText       = malloc(uPlainTextSize))) { free(pPaddedPlainText); free(pCipherText); return -1; }

    memset(pPaddedPlainText, 0, uPlainTextSize);
    memcpy(pPaddedPlainText, g_PlainText, strlen((char*)g_PlainText));

    Aes128ECBEncrypt(pPaddedPlainText, uPlainTextSize, pCipherText, g_AesKey, &bEncrypted);
    if (!bEncrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[ECB] Encryption successful\n");

    Aes128ECBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, &bDecrypted);
    if (!bDecrypted) { free(pPaddedPlainText); free(pCipherText); free(pPlainText); return -1; }
    printf("[ECB] Decryption successful: %s\n", pPlainText);

    free(pPaddedPlainText);
    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes128CFB() { 

    TEST_HEADER_128("CFB");

    unsigned __int64  uPlainTextSize   = strlen((char*)g_PlainText);
    unsigned char*    pCipherText      = NULL;
    unsigned char*    pPlainText       = NULL;
    unsigned char     bEncrypted       = FALSE;
    unsigned char     bDecrypted       = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes128CFBEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CFB] Encryption successful\n");

    Aes128CFBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CFB] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}

int TestAes128CTR() { 

    TEST_HEADER_128("CTR");

    unsigned __int64  uPlainTextSize   = strlen((char*)g_PlainText);
    unsigned char*    pCipherText      = NULL;
    unsigned char*    pPlainText       = NULL;
    unsigned char     bEncrypted       = FALSE;
    unsigned char     bDecrypted       = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes128CTREncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CTR] Encryption successful\n");

    Aes128CTRDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[CTR] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes128GCM() { 

    TEST_HEADER_128("GCM");

    unsigned __int64  uPlainTextSize   = strlen((char*)g_PlainText);
    unsigned char*    pCipherText      = NULL;
    unsigned char*    pPlainText       = NULL;
    unsigned char     u8Tag[16]        = { 0 };
    unsigned char     bEncrypted       = FALSE;
    unsigned char     bDecrypted       = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes128GCMEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesNonce, u8Tag, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[GCM] Encryption successful\n");

    Aes128GCMDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesNonce, u8Tag, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[GCM] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}


int TestAes128OCB() { 

    TEST_HEADER_128("OCB");

    unsigned __int64  uPlainTextSize   = strlen((char*)g_PlainText);
    unsigned char*    pCipherText      = NULL;
    unsigned char*    pPlainText       = NULL;
    unsigned char     u8Tag[16]        = { 0 };
    unsigned char     bEncrypted       = FALSE;
    unsigned char     bDecrypted       = FALSE;

    if (!(pCipherText = malloc(uPlainTextSize))) return -1;
    if (!(pPlainText  = malloc(uPlainTextSize))) { free(pCipherText); return -1; }

    Aes128OCBEncrypt(g_PlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesNonce, u8Tag, &bEncrypted);
    if (!bEncrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[OCB] Encryption successful\n");

    Aes128OCBDecrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesNonce, u8Tag, &bDecrypted);
    if (!bDecrypted) { free(pCipherText); free(pPlainText); return -1; }
    printf("[OCB] Decryption successful: %.*s\n", (int)uPlainTextSize, pPlainText);

    free(pCipherText);
    free(pPlainText);
    return 0;
}




int main(void) 
{
    if (TestAes256CBC() != 0) return 1;
    if (TestAes256ECB() != 0) return 2;
    if (TestAes256CFB() != 0) return 3;
    if (TestAes256CTR() != 0) return 4;
    if (TestAes256GCM() != 0) return 5;
    if (TestAes256OCB() != 0) return 6;
    
    printf("[*] All 256-bit AES tests passed!\n");
    
    if (TestAes128CBC() != 0) return 7;
    if (TestAes128ECB() != 0) return 8;
    if (TestAes128CFB() != 0) return 8;
    if (TestAes128CTR() != 0) return 10;
    if (TestAes128GCM() != 0) return 11;
    if (TestAes128OCB() != 0) return 12;

    printf("[*] All 128-bit AES tests passed!\n");
    
    return 0;
}

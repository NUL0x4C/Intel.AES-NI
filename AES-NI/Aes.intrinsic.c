#include <Windows.h>
#include <wmmintrin.h>
#include <stdio.h>


#include "Aes.intrinsic.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static void Aes256CBCKeyExpansion(const unsigned char* pAesKey, __m128i* pKeySchedule)
{
    __m128i xmmTemp1, xmmTemp2, xmmTemp3;

    // Load master key
    xmmTemp1 = _mm_loadu_si128((const __m128i*)pAesKey);
    xmmTemp2 = _mm_loadu_si128((const __m128i*)(pAesKey + 16));
    pKeySchedule[0] = xmmTemp1;
    pKeySchedule[1] = xmmTemp2;

    // Round 1
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x01);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[2] = xmmTemp1;

    // Round 1 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[3] = xmmTemp2;

    // Round 2
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x02);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[4] = xmmTemp1;

    // Round 2 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[5] = xmmTemp2;

    // Round 3
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x04);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[6] = xmmTemp1;

    // Round 3 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[7] = xmmTemp2;

    // Round 4
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x08);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[8] = xmmTemp1;

    // Round 4 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[9] = xmmTemp2;

    // Round 5
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x10);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[10] = xmmTemp1;

    // Round 5 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[11] = xmmTemp2;

    // Round 6
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x20);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[12] = xmmTemp1;

    // Round 6 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[13] = xmmTemp2;

    // Round 7
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x40);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[14] = xmmTemp1;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static void Aes128CBCKeyExpansion(const unsigned char* pAesKey, __m128i* pKeySchedule)
{
    __m128i xmmTemp1, xmmTemp2;

    // Load master key
    xmmTemp1 = _mm_loadu_si128((const __m128i*)pAesKey);
    pKeySchedule[0] = xmmTemp1;

    // Round 1
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x01);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[1] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 2
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x02);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[2] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 3
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x04);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[3] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 4
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x08);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[4] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 5
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x10);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[5] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 6
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x20);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[6] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 7
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x40);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[7] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 8
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x80);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[8] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 9
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x1B);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[9] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 10
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x36);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[10] = _mm_xor_si128(xmmTemp1, xmmTemp2);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes256CBCEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted)
{
    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;
	if (uPlainTextSize % 16 != 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

    for (unsigned __int64 uIndex = 0; uIndex < uPlainTextSize; uIndex += 16)
    {
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 14; iRound++)
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);

        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmBlock);
        xmmChain = xmmBlock;
    }

	*pbEncrypted = TRUE;
}


void Aes256CBCDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted)
{

    if (!pbDecrypted) return;
    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;
    if (uCipherTextSize % 16 != 0) return;

    __m128i xmmEncKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmEncKeySchedule);

    __m128i xmmDecKeySchedule[15];
    xmmDecKeySchedule[0] = xmmEncKeySchedule[14];
    for (int i = 1; i < 14; i++)
        xmmDecKeySchedule[i] = _mm_aesimc_si128(xmmEncKeySchedule[14 - i]);
    xmmDecKeySchedule[14] = xmmEncKeySchedule[0];

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);


    for (unsigned __int64 uIndex = 0; uIndex < uCipherTextSize; uIndex += 16)
    {
        __m128i xmmCipherBlock = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmTemp = xmmCipherBlock;

        __m128i xmmBlock = _mm_xor_si128(xmmCipherBlock, xmmDecKeySchedule[0]);

        for (int iRound = 1; iRound < 14; iRound++)
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);

        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[14]);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);

        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmBlock);

        xmmChain = xmmTemp;
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128CBCEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted) {
	
    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;
	
    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;
	if (uPlainTextSize % 16 != 0) return;
	
    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

    for (unsigned __int64 uIndex = 0; uIndex < uPlainTextSize; uIndex += 16)
    {
        
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 10; ++iRound) 
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);

        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmBlock);
        
        xmmChain = xmmBlock;
    }

    *pbEncrypted = TRUE;
}


void Aes128CBCDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted) {
	
    if (!pbDecrypted) return;
	
    *pbDecrypted = FALSE;
	
    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;
	if (uCipherTextSize % 16 != 0) return;
	
    __m128i xmmEncKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmEncKeySchedule);

    __m128i xmmDecKeySchedule[11];
    xmmDecKeySchedule[0] = xmmEncKeySchedule[10];
    
    for (int iRound = 1; iRound < 10; ++iRound)
        xmmDecKeySchedule[iRound] = _mm_aesimc_si128(xmmEncKeySchedule[10 - iRound]);
    
    xmmDecKeySchedule[10] = xmmEncKeySchedule[0];

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

    for (unsigned __int64 uIndex = 0; uIndex < uCipherTextSize; uIndex += 16)
    {
       
        __m128i xmmCipherBlock = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmTemp = xmmCipherBlock;
        __m128i xmmBlock = _mm_aesdec_si128(_mm_xor_si128(xmmCipherBlock, xmmDecKeySchedule[0]), xmmDecKeySchedule[1]);
        
        for (int iRound = 2; iRound < 10; ++iRound)
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);
        
        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[10]);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);

        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmBlock);
        
        xmmChain = xmmTemp;
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes256ECBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;
    
    if (!pPlainText || !pCipherText || !pAesKey || uPlainTextSize == 0) return;
    if (uPlainTextSize % 16 != 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    for (unsigned __int64 uIndex = 0; uIndex < uPlainTextSize; uIndex += 16) 
    {
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound) 
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);
        
        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmBlock);
    }

    *pbEncrypted = TRUE;
}


void Aes256ECBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, OUT PBOOLEAN pbDecrypted) {
	
    if (!pbDecrypted) return;
	
    *pbDecrypted = FALSE;
	
    if (!pCipherText || !pPlainText || !pAesKey || uCipherTextSize == 0) return;
	if (uCipherTextSize % 16 != 0) return;
	
    __m128i xmmEncKeySchedule[15];
	Aes256CBCKeyExpansion(pAesKey, xmmEncKeySchedule);
	
    __m128i xmmDecKeySchedule[15];
	xmmDecKeySchedule[0] = xmmEncKeySchedule[14];

	for (int iRound = 1; iRound < 14; ++iRound)
		xmmDecKeySchedule[iRound] = _mm_aesimc_si128(xmmEncKeySchedule[14 - iRound]);

	xmmDecKeySchedule[14] = xmmEncKeySchedule[0];
	
    for (unsigned __int64 uIndex = 0; uIndex < uCipherTextSize; uIndex += 16)
	{
        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmBlock = _mm_aesdec_si128(_mm_xor_si128(xmmCipher, xmmDecKeySchedule[0]), xmmDecKeySchedule[1]);
        
        for (int iRound = 2; iRound < 14; ++iRound)
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);
        
        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[14]);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmBlock);
	}

	*pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128ECBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || uPlainTextSize == 0) return;
    if (uPlainTextSize % 16 != 0) return;


    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    for (unsigned __int64 uIndex = 0; uIndex < uPlainTextSize; uIndex += 16) 
    {
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);
        
        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmBlock);
    }

    *pbEncrypted = TRUE;
}


void Aes128ECBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, OUT PBOOLEAN pbDecrypted) {
	
    if (!pbDecrypted) return;
	
    *pbDecrypted = FALSE;
	
    if (!pCipherText || !pPlainText || !pAesKey || uCipherTextSize == 0) return;
	if (uCipherTextSize % 16 != 0) return;
	
    __m128i xmmEncKeySchedule[11];
	Aes128CBCKeyExpansion(pAesKey, xmmEncKeySchedule);
	
    __m128i xmmDecKeySchedule[11];
	xmmDecKeySchedule[0] = xmmEncKeySchedule[10];
	
    for (int iRound = 1; iRound < 10; ++iRound)
		xmmDecKeySchedule[iRound] = _mm_aesimc_si128(xmmEncKeySchedule[10 - iRound]);
	
    xmmDecKeySchedule[10] = xmmEncKeySchedule[0];
	
    for (unsigned __int64 uIndex = 0; uIndex < uCipherTextSize; uIndex += 16)
	{
        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmBlock = _mm_aesdec_si128(_mm_xor_si128(xmmCipher, xmmDecKeySchedule[0]), xmmDecKeySchedule[1]);

        for (int iRound = 2; iRound < 10; ++iRound) 
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);
        
        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[10]);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmBlock);
    }
	
    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



void Aes256CFBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uPlainTextSize; uIndex += 16)
    {
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        __m128i xmmPlain = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCipher = _mm_xor_si128(xmmPlain, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCipher);

        xmmChain = xmmCipher;
    }

    if (uIndex < uPlainTextSize)
    {

        unsigned int uBytesLeft = (unsigned int)(uPlainTextSize - uIndex);
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        unsigned char u8KeystreamBuf[16];
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pCipherText[uIndex + j] = pPlainText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbEncrypted = TRUE;
}


void Aes256CFBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted)
{
    if (!pbDecrypted) return;

    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16)
    {
        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        __m128i xmmPlain = _mm_xor_si128(xmmCipher, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPlain);

        xmmChain = xmmCipher;
    }

    if (uIndex < uCipherTextSize)
    {
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        unsigned char u8KeystreamBuf[16];
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pPlainText[uIndex + j] = pCipherText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbDecrypted = TRUE;
}



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128CFBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uPlainTextSize; uIndex += 16)
    {
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        __m128i xmmPlain = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCipher = _mm_xor_si128(xmmPlain, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCipher);

        xmmChain = xmmCipher;
    }

    if (uIndex < uPlainTextSize)
    {

        unsigned int uBytesLeft = (unsigned int)(uPlainTextSize - uIndex);
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        unsigned char u8KeystreamBuf[16];
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pCipherText[uIndex + j] = pPlainText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbEncrypted = TRUE;
}


void Aes128CFBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted) {
	
    if (!pbDecrypted) return;

    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16)
    {
        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        __m128i xmmPlain = _mm_xor_si128(xmmCipher, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPlain);

        xmmChain = xmmCipher;
    }

    if (uIndex < uCipherTextSize)
    {
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        __m128i xmmKeystream = xmmChain;

        for (int iRound = 0; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        unsigned char u8KeystreamBuf[16];
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pPlainText[uIndex + j] = pCipherText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes256CTREncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;
    
    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmCtr = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uPlainTextSize; uIndex += 16) 
    {
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        __m128i xmmPlain = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCipher = _mm_xor_si128(xmmPlain, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCipher);
    }

    if (uIndex < uPlainTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uPlainTextSize - uIndex);
        unsigned char u8KeystreamBuf[16];

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pCipherText[uIndex + j] = pPlainText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbEncrypted = TRUE;
}


void Aes256CTRDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted) {

    if (!pbDecrypted) return;
    
    *pbDecrypted = FALSE;
    
    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmCtr = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16) 
    {
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);

        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmPlain = _mm_xor_si128(xmmCipher, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPlain);
    }

    if (uIndex < uCipherTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        unsigned char u8KeystreamBuf[16];

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pPlainText[uIndex + j] = pCipherText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128CTREncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;
    
    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmCtr = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uPlainTextSize; uIndex += 16) 
    {
        
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        __m128i xmmPlain = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCipher = _mm_xor_si128(xmmPlain, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCipher);
    }

    if (uIndex < uPlainTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uPlainTextSize - uIndex);
        unsigned char u8KeystreamBuf[16];

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pCipherText[uIndex + j] = pPlainText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbEncrypted = TRUE;
}


void Aes128CTRDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted) {

    if (!pbDecrypted) return;
    
    *pbDecrypted = FALSE;
    
    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmCtr = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16) 
    {
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        __m128i xmmCipher = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmPlain = _mm_xor_si128(xmmCipher, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPlain);
    }

    if (uIndex < uCipherTextSize) 
    {
        
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        unsigned char u8KeystreamBuf[16];

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);
        
        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pPlainText[uIndex + j] = pCipherText[uIndex + j] ^ u8KeystreamBuf[j];
    }

    *pbDecrypted = TRUE;

}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


static __m128i GcmComputeHashSubkey256(const __m128i* pEncKeySchedule) 
{

    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmHashSub = xmmZero;

    xmmHashSub = _mm_xor_si128(xmmHashSub, pEncKeySchedule[0]);

    for (int iRound = 1; iRound < 14; ++iRound) {
        xmmHashSub = _mm_aesenc_si128(xmmHashSub, pEncKeySchedule[iRound]);
    }

    xmmHashSub = _mm_aesenclast_si128(xmmHashSub, pEncKeySchedule[14]);
    return xmmHashSub;
}


static __m128i GcmComputeHashSubkey128(const __m128i* pEncKeySchedule)
{
    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmHashSub = xmmZero;

    xmmHashSub = _mm_xor_si128(xmmHashSub, pEncKeySchedule[0]);
    for (int iRound = 1; iRound < 10; ++iRound) {
        xmmHashSub = _mm_aesenc_si128(xmmHashSub, pEncKeySchedule[iRound]);
    }
    xmmHashSub = _mm_aesenclast_si128(xmmHashSub, pEncKeySchedule[10]);
    return xmmHashSub;
}


static __m128i GcmGHashMultiply(__m128i xmmX, __m128i xmmY) 
{
    __m128i xmmT0 = _mm_clmulepi64_si128(xmmX, xmmY, 0x00);
    __m128i xmmT1 = _mm_clmulepi64_si128(xmmX, xmmY, 0x10);
    __m128i xmmT2 = _mm_clmulepi64_si128(xmmX, xmmY, 0x01);
    __m128i xmmT3 = _mm_clmulepi64_si128(xmmX, xmmY, 0x11);

    __m128i xmmMid = _mm_xor_si128(xmmT1, xmmT2);
    xmmMid = _mm_xor_si128(xmmMid, _mm_slli_si128(xmmMid, 8));
    
    __m128i xmmLo = _mm_xor_si128(xmmT0, _mm_srli_si128(xmmMid, 8));
    __m128i xmmHi = _mm_xor_si128(xmmT3, _mm_slli_si128(xmmMid, 8));

    __m128i xmmR = _mm_set_epi32(0xe1000000, 0, 0, 0);
    __m128i xmmV1 = _mm_clmulepi64_si128(xmmHi, xmmR, 0x10);
    __m128i xmmV2 = _mm_clmulepi64_si128(xmmHi, xmmR, 0x11);
    __m128i xmmRed = _mm_xor_si128(xmmV1, xmmV2);

    return _mm_xor_si128(xmmLo, xmmRed);
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes256GCMEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;
    
    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmH = GcmComputeHashSubkey256(xmmKeySchedule);
    
    __m128i xmmJ0 = _mm_loadu_si128((const __m128i*)pAesIv);
    xmmJ0 = _mm_insert_epi32(xmmJ0, 1, 3);

    __m128i xmmCtGH = _mm_setzero_si128();
    __m128i xmmCtr = xmmJ0;
    unsigned __int64 uIndex = 0;

    while (uIndex + 16 <= uPlainTextSize) 
    {
        unsigned int ctrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, ctrLow, 3);

        __m128i xmmKS = xmmCtr;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[14]);

        __m128i xmmPT = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCT = _mm_xor_si128(xmmPT, xmmKS);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCT);

        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCT);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);

        uIndex += 16;
    }

    if (uIndex < uPlainTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uPlainTextSize - uIndex);
        unsigned char u8Keystream[16] = { 0 };
        unsigned char u8CT[16] = { 0 };

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKS = xmmCtr;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)u8Keystream, xmmKS);

        for (unsigned int j = 0; j < uBytesLeft; ++j) 
        {
            u8CT[j] = pPlainText[uIndex + j] ^ u8Keystream[j];
            pCipherText[uIndex + j] = u8CT[j];
        }

        __m128i xmmCTpad = _mm_loadu_si128((const __m128i*)u8CT);
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCTpad);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }

    __m128i xmmLen = _mm_set_epi64x(0LL, (long long)(uPlainTextSize * 8));
    xmmCtGH = _mm_xor_si128(xmmCtGH, xmmLen);
    xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);

    __m128i xmmS = xmmJ0;
    xmmS = _mm_xor_si128(xmmS, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmS = _mm_aesenc_si128(xmmS, xmmKeySchedule[iRound]);
    
    xmmS = _mm_aesenclast_si128(xmmS, xmmKeySchedule[14]);

    __m128i xmmTag = _mm_xor_si128(xmmS, xmmCtGH);
    _mm_storeu_si128((__m128i*)pAuthTag, xmmTag);

    *pbEncrypted = TRUE;
}


void Aes256GCMDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbDecrypted) {

    if (!pbDecrypted) return;
    
    *pbDecrypted = FALSE;
    
    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmH = GcmComputeHashSubkey256(xmmKeySchedule);
    __m128i xmmJ0 = _mm_loadu_si128((const __m128i*)pAesIv);
    xmmJ0 = _mm_insert_epi32(xmmJ0, 1, 3);

    __m128i xmmCtGH = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16) 
    {
        __m128i xmmCT = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCT);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }

    if (uIndex < uCipherTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        unsigned char u8CTpad[16] = { 0 };
       
        for (unsigned int j = 0; j < uBytesLeft; ++j)
            u8CTpad[j] = pCipherText[uIndex + j];
        
        __m128i xmmCTpad = _mm_loadu_si128((const __m128i*)u8CTpad);
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCTpad);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }

    __m128i xmmLen = _mm_set_epi64x(0LL, (long long)(uCipherTextSize * 8));
    xmmCtGH = _mm_xor_si128(xmmCtGH, xmmLen);
    xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);

    __m128i xmmS = xmmJ0;
    xmmS = _mm_xor_si128(xmmS, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmS = _mm_aesenc_si128(xmmS, xmmKeySchedule[iRound]);
    
    xmmS = _mm_aesenclast_si128(xmmS, xmmKeySchedule[14]);
    __m128i xmmTag = _mm_xor_si128(xmmS, xmmCtGH);
    
    unsigned char u8Expected[16];
    unsigned char u8Diff = 0;

    _mm_storeu_si128((__m128i*)u8Expected, xmmTag);
    
    for (int i = 0; i < 16; ++i)
        u8Diff |= (u8Expected[i] ^ pAuthTag[i]);
    
	if (u8Diff != 0) return;                 // Authentication Failed, Halt Decryption

    __m128i xmmCtr = xmmJ0;
    uIndex = 0;
    
    while (uIndex + 16 <= uCipherTextSize) 
    {
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKS = xmmCtr;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[14]);

        __m128i xmmCT = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmPT = _mm_xor_si128(xmmCT, xmmKS);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPT);

        uIndex += 16;
    }

    if (uIndex < uCipherTextSize) 
    {
        unsigned int uBytesLeft = (unsigned int)(uCipherTextSize - uIndex);
        unsigned char u8Keystream[16] = { 0 };
        unsigned char u8PT[16] = { 0 };

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKS = xmmCtr;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)u8Keystream, xmmKS);

        for (unsigned int j = 0; j < uBytesLeft; ++j) 
        {
            u8PT[j] = pCipherText[uIndex + j] ^ u8Keystream[j];
            pPlainText[uIndex + j] = u8PT[j];
        }
    }

    *pbDecrypted = TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128GCMEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbEncrypted) {
    
    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;
    
    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmH = GcmComputeHashSubkey128(xmmKeySchedule);

    unsigned char u8J0[16] = { 0 };
    memcpy(u8J0, pAesIv, 12);
    u8J0[15] = 1;
    __m128i xmmJ0 = _mm_loadu_si128((const __m128i*)u8J0);

    __m128i xmmCtGH = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uPlainTextSize; uIndex += 16) 
    {
        unsigned int ctr = _mm_extract_epi32(xmmJ0, 3) + 1;
        xmmJ0 = _mm_insert_epi32(xmmJ0, ctr, 3);
        __m128i xmmKS = xmmJ0;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[10]);

        __m128i xmmPT = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmCT = _mm_xor_si128(xmmPT, xmmKS);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCT);

        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCT);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }
    
    if (uIndex < uPlainTextSize) 
    {
        unsigned int left = (unsigned)(uPlainTextSize - uIndex);
        unsigned int ctr = _mm_extract_epi32(xmmJ0, 3) + 1;
        
        xmmJ0 = _mm_insert_epi32(xmmJ0, ctr, 3);
        __m128i xmmKS = xmmJ0;
        xmmKS = _mm_xor_si128(xmmKS, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[10]);
        
        unsigned char u8Buf[16]; _mm_storeu_si128((__m128i*)u8Buf, xmmKS);
        unsigned char u8CT[16] = { 0 };
        
        for (unsigned i = 0; i < left; ++i) 
        {
            u8CT[i] = pPlainText[uIndex + i] ^ u8Buf[i];
            pCipherText[uIndex + i] = u8CT[i];
        }
        
        __m128i xmmCTpad = _mm_loadu_si128((const __m128i*)u8CT);
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCTpad);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }

    __m128i xmmLen = _mm_set_epi64x(0LL, (long long)(uPlainTextSize * 8));
    xmmCtGH = _mm_xor_si128(xmmCtGH, xmmLen);
    xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);

    __m128i xmmS = _mm_xor_si128(_mm_loadu_si128((const __m128i*)u8J0), xmmKeySchedule[0]);

    for (int iRound = 1; iRound < 10; ++iRound)
        xmmS = _mm_aesenc_si128(xmmS, xmmKeySchedule[iRound]);

    xmmS = _mm_aesenclast_si128(xmmS, xmmKeySchedule[10]);

    __m128i xmmTag = _mm_xor_si128(xmmS, xmmCtGH);
    _mm_storeu_si128((__m128i*)pAuthTag, xmmTag);

    *pbEncrypted = TRUE;
}


void Aes128GCMDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbDecrypted) {
    
    if (!pbDecrypted) return;

    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmH = GcmComputeHashSubkey128(xmmKeySchedule);

    unsigned char u8J0[16] = { 0 };
    memcpy(u8J0, pAesIv, 12);
    u8J0[15] = 1;
    __m128i xmmJ0 = _mm_loadu_si128((const __m128i*)u8J0);

    __m128i xmmCtGH = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;
    
    for (; uIndex + 16 <= uCipherTextSize; uIndex += 16) 
    {
        __m128i xmmCt = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCt);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }
    
    if (uIndex < uCipherTextSize) 
    {
        unsigned int left = (unsigned)(uCipherTextSize - uIndex);
        unsigned char u8Buf[16] = { 0 };

        memcpy(u8Buf, pCipherText + uIndex, left);
        
        __m128i xmmCtPad = _mm_loadu_si128((const __m128i*)u8Buf);
        xmmCtGH = _mm_xor_si128(xmmCtGH, xmmCtPad);
        xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);
    }

    __m128i xmmLen = _mm_set_epi64x(0LL, (long long)(uCipherTextSize * 8));
    xmmCtGH = _mm_xor_si128(xmmCtGH, xmmLen);
    xmmCtGH = GcmGHashMultiply(xmmCtGH, xmmH);

    __m128i xmmS = _mm_xor_si128(xmmJ0, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 10; ++iRound)
        xmmS = _mm_aesenc_si128(xmmS, xmmKeySchedule[iRound]);
    
    xmmS = _mm_aesenclast_si128(xmmS, xmmKeySchedule[10]);
    __m128i xmmTag = _mm_xor_si128(xmmS, xmmCtGH);

    unsigned char u8Expected[16];
    unsigned char u8Diff = 0;
    _mm_storeu_si128((__m128i*)u8Expected, xmmTag);

    for (int i = 0; i < 16; ++i)
        u8Diff |= (u8Expected[i] ^ pAuthTag[i]);
    
	if (u8Diff) return;             // Authentication Failed, Halt Decryption

    __m128i xmmCtr = xmmJ0;
    uIndex = 0;

    while (uIndex + 16 <= uCipherTextSize) 
    {
        unsigned int ctr = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, ctr, 3);

        __m128i xmmKS = _mm_xor_si128(xmmCtr, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[10]);

        __m128i xmmCt = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmPt = _mm_xor_si128(xmmCt, xmmKS);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPt);

        uIndex += 16;
    }

    if (uIndex < uCipherTextSize) 
    {
        unsigned int uBytesLeft = (unsigned)(uCipherTextSize - uIndex);
        unsigned int ctrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, ctrLow, 3);

        __m128i xmmKS = _mm_xor_si128(xmmCtr, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKS = _mm_aesenc_si128(xmmKS, xmmKeySchedule[iRound]);
        
        xmmKS = _mm_aesenclast_si128(xmmKS, xmmKeySchedule[10]);

        unsigned char u8Keystream[16];
        _mm_storeu_si128((__m128i*)u8Keystream, xmmKS);

        for (unsigned int i = 0; i < uBytesLeft; ++i)
            pPlainText[uIndex + i] = pCipherText[uIndex + i] ^ u8Keystream[i];
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static __m128i OcbMulAlpha(__m128i xmmT) 
{
    __m128i xmmHi = _mm_srli_epi64(xmmT, 63);
    __m128i xmmLo = _mm_slli_si128(xmmT, 1);
    
    xmmHi = _mm_shuffle_epi32(xmmHi, _MM_SHUFFLE(2, 3, 0, 1));
    xmmLo = _mm_xor_si128(xmmLo, _mm_and_si128(xmmHi, _mm_set_epi32(0x00000087, 0, 0, 0)));
    
    return xmmLo;
}

void Aes256OCBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv) return;

    __m128i xmmKeySchedule[15];
    Aes256CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmL = _mm_xor_si128(xmmZero, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmL = _mm_aesenc_si128(xmmL, xmmKeySchedule[iRound]);

    xmmL = _mm_aesenclast_si128(xmmL, xmmKeySchedule[14]);

    __m128i xmmLs = OcbMulAlpha(xmmL);
    __m128i xmmLd = OcbMulAlpha(xmmLs);

    unsigned char u8NonceBlk[16] = { 0 };
    memcpy(u8NonceBlk, pAesIv, 12);
    u8NonceBlk[15] = 1;  
    __m128i xmmOffset = _mm_loadu_si128((const __m128i*)u8NonceBlk);
    xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

    __m128i xmmSum = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;

    while (uIndex + 16 <= uPlainTextSize) 
    {
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLd);

        __m128i xmmPT = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmX = _mm_xor_si128(xmmPT, xmmOffset);

        __m128i xmmY = _mm_xor_si128(xmmX, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmY = _mm_aesenc_si128(xmmY, xmmKeySchedule[iRound]);
        
        xmmY = _mm_aesenclast_si128(xmmY, xmmKeySchedule[14]);

        __m128i xmmCT = _mm_xor_si128(xmmY, xmmOffset);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCT);

        xmmSum = _mm_xor_si128(xmmSum, xmmPT);
        uIndex += 16;
    }

    unsigned char u8Tmp[16] = { 0 }, u8Pad[16];

    if (uIndex < uPlainTextSize) 
    {
        unsigned int uLeft = (unsigned int)(uPlainTextSize - uIndex);

        xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

        __m128i xmmPad = _mm_xor_si128(xmmOffset, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 14; ++iRound)
            xmmPad = _mm_aesenc_si128(xmmPad, xmmKeySchedule[iRound]);
        
        xmmPad = _mm_aesenclast_si128(xmmPad, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)u8Pad, xmmPad);

        for (unsigned i = 0; i < uLeft; ++i) 
        {
            unsigned char p = pPlainText[uIndex + i];
            unsigned char c = p ^ u8Pad[i];
            pCipherText[uIndex + i] = c;
            u8Tmp[i] = p;
        }
        
        unsigned char u8Block[16] = { 0 };
        memcpy(u8Block, u8Tmp, uLeft);
        
        __m128i xmmTail = _mm_loadu_si128((const __m128i*)u8Block);
        xmmSum = _mm_xor_si128(xmmSum, xmmTail);
    }

    __m128i xmmT = _mm_xor_si128(xmmSum, _mm_xor_si128(xmmOffset, xmmL));
    __m128i xmmTag = _mm_xor_si128(xmmT, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmTag = _mm_aesenc_si128(xmmTag, xmmKeySchedule[iRound]);
    
    xmmTag = _mm_aesenclast_si128(xmmTag, xmmKeySchedule[14]);
    _mm_storeu_si128((__m128i*)pAuthTag, xmmTag);

    *pbEncrypted = TRUE;
}

void Aes256OCBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbDecrypted) {

    if (!pbDecrypted) return;

    *pbDecrypted = FALSE;
    
    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmEncKey[15], xmmDecKey[15];
    Aes256CBCKeyExpansion(pAesKey, xmmEncKey);
    xmmDecKey[0] = xmmEncKey[14];
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmDecKey[iRound] = _mm_aesimc_si128(xmmEncKey[14 - iRound]);
    
    xmmDecKey[14] = xmmEncKey[0];

    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmL = _mm_xor_si128(xmmZero, xmmEncKey[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmL = _mm_aesenc_si128(xmmL, xmmEncKey[iRound]);
    
    xmmL = _mm_aesenclast_si128(xmmL, xmmEncKey[14]);
    
    __m128i xmmLs = OcbMulAlpha(xmmL);
    __m128i xmmLd = OcbMulAlpha(xmmLs);

    unsigned char u8NonceBlk[16] = { 0 };
    memcpy(u8NonceBlk, pAesIv, 12);
    u8NonceBlk[15] = 1;
    __m128i xmmOffset = _mm_loadu_si128((const __m128i*)u8NonceBlk);
    xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

    __m128i xmmChecksum = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;
    
    while (uIndex + 16 <= uCipherTextSize) 
    {
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLd);

        __m128i xmmCT = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmX = _mm_xor_si128(xmmCT, xmmOffset);
        __m128i xmmY = _mm_xor_si128(xmmX, xmmDecKey[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmY = _mm_aesdec_si128(xmmY, xmmDecKey[iRound]);
        
        xmmY = _mm_aesdeclast_si128(xmmY, xmmDecKey[14]);
        __m128i xmmPT = _mm_xor_si128(xmmY, xmmOffset);

        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPT);
        xmmChecksum = _mm_xor_si128(xmmChecksum, xmmPT);

        uIndex += 16;
    }

    if (uIndex < uCipherTextSize) 
    {
        unsigned int uLeft = (unsigned int)(uCipherTextSize - uIndex);
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);
        
        __m128i xmmPad = _mm_xor_si128(xmmOffset, xmmEncKey[0]);
        
        for (int iRound = 1; iRound < 14; ++iRound)
            xmmPad = _mm_aesenc_si128(xmmPad, xmmEncKey[iRound]);
        
        xmmPad = _mm_aesenclast_si128(xmmPad, xmmEncKey[14]);

        unsigned char u8Pad[16];
        _mm_storeu_si128((__m128i*)u8Pad, xmmPad);

        unsigned char u8Tail[16] = { 0 };
        
        for (unsigned i = 0; i < uLeft; ++i) 
        {
            unsigned char c = pCipherText[uIndex + i];
            unsigned char p = c ^ u8Pad[i];
            pPlainText[uIndex + i] = p;
            u8Tail[i] = p;
        }
        
        __m128i xmmTail = _mm_loadu_si128((const __m128i*)u8Tail);
        xmmChecksum = _mm_xor_si128(xmmChecksum, xmmTail);
    }

    __m128i xmmT = _mm_xor_si128(xmmChecksum, _mm_xor_si128(xmmOffset, xmmL));
    __m128i xmmCalcTag = _mm_xor_si128(xmmT, xmmEncKey[0]);
    
    for (int iRound = 1; iRound < 14; ++iRound)
        xmmCalcTag = _mm_aesenc_si128(xmmCalcTag, xmmEncKey[iRound]);
    
    xmmCalcTag = _mm_aesenclast_si128(xmmCalcTag, xmmEncKey[14]);

    unsigned char u8Expected[16];
    unsigned char u8Diff = 0;
    _mm_storeu_si128((__m128i*)u8Expected, xmmCalcTag);

    for (int i = 0; i < 16; ++i)
        u8Diff |= u8Expected[i] ^ pAuthTag[i];
    
    if (u8Diff != 0) 
    {
		memset(pPlainText, 0, (size_t)uCipherTextSize);     // Authentication Failed, Clear Output Buffer
        return;
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


void Aes128OCBEncrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbEncrypted) {

    if (!pbEncrypted) return;

    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv) return;


    __m128i xmmKeySchedule[11];
    Aes128CBCKeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmL = _mm_xor_si128(xmmZero, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 10; ++iRound)
        xmmL = _mm_aesenc_si128(xmmL, xmmKeySchedule[iRound]);
    
    xmmL = _mm_aesenclast_si128(xmmL, xmmKeySchedule[10]);

    __m128i xmmLs = OcbMulAlpha(xmmL);
    __m128i xmmLd = OcbMulAlpha(xmmLs);

    unsigned char u8NonceBlk[16] = { 0 };
    memcpy(u8NonceBlk, pAesIv, 12);
    u8NonceBlk[15] = 1;
    __m128i xmmOffset = _mm_loadu_si128((const __m128i*)u8NonceBlk);
    xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

    __m128i xmmSum = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;

    while (uIndex + 16 <= uPlainTextSize) 
    {
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLd);

        __m128i xmmPT = _mm_loadu_si128((const __m128i*)(pPlainText + uIndex));
        __m128i xmmX = _mm_xor_si128(xmmPT, xmmOffset);

        __m128i xmmY = _mm_xor_si128(xmmX, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmY = _mm_aesenc_si128(xmmY, xmmKeySchedule[iRound]);
        
        xmmY = _mm_aesenclast_si128(xmmY, xmmKeySchedule[10]);

        __m128i xmmCT = _mm_xor_si128(xmmY, xmmOffset);
        _mm_storeu_si128((__m128i*)(pCipherText + uIndex), xmmCT);

        xmmSum = _mm_xor_si128(xmmSum, xmmPT);
        uIndex += 16;
    }

    unsigned char u8Tmp[16] = { 0 }, u8Pad[16];

    if (uIndex < uPlainTextSize) 
    {
        unsigned int uLeft = (unsigned int)(uPlainTextSize - uIndex);

        xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

        __m128i xmmPad = _mm_xor_si128(xmmOffset, xmmKeySchedule[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmPad = _mm_aesenc_si128(xmmPad, xmmKeySchedule[iRound]);
        
        xmmPad = _mm_aesenclast_si128(xmmPad, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)u8Pad, xmmPad);

        for (unsigned i = 0; i < uLeft; ++i) 
        {
            unsigned char p = pPlainText[uIndex + i];
            unsigned char c = p ^ u8Pad[i];
            pCipherText[uIndex + i] = c;
            u8Tmp[i] = p;
        }

        unsigned char u8Block[16] = { 0 };
        memcpy(u8Block, u8Tmp, uLeft);
        
        __m128i xmmTail = _mm_loadu_si128((const __m128i*)u8Block);
        xmmSum = _mm_xor_si128(xmmSum, xmmTail);
    }

    __m128i xmmT = _mm_xor_si128(xmmSum, _mm_xor_si128(xmmOffset, xmmL));
    __m128i xmmTag = _mm_xor_si128(xmmT, xmmKeySchedule[0]);
    
    for (int iRound = 1; iRound < 10; ++iRound)
        xmmTag = _mm_aesenc_si128(xmmTag, xmmKeySchedule[iRound]);
    
    xmmTag = _mm_aesenclast_si128(xmmTag, xmmKeySchedule[10]);
    _mm_storeu_si128((__m128i*)pAuthTag, xmmTag);

    *pbEncrypted = TRUE;
}


void Aes128OCBDecrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, IN unsigned char* pAuthTag, OUT PBOOLEAN pbDecrypted) {

    if (!pbDecrypted) return;

    *pbDecrypted = FALSE;

    if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;

    __m128i xmmEncKey[11], xmmDecKey[11];
    Aes128CBCKeyExpansion(pAesKey, xmmEncKey);

    xmmDecKey[0] = xmmEncKey[10];
    for (int iRound = 1; iRound < 10; ++iRound) {
        xmmDecKey[iRound] = _mm_aesimc_si128(xmmEncKey[10 - iRound]);
    }
    xmmDecKey[10] = xmmEncKey[0];

    __m128i xmmZero = _mm_setzero_si128();
    __m128i xmmL = _mm_xor_si128(xmmZero, xmmEncKey[0]);
    
    for (int iRound = 1; iRound < 10; ++iRound)
        xmmL = _mm_aesenc_si128(xmmL, xmmEncKey[iRound]);
    
    
    xmmL = _mm_aesenclast_si128(xmmL, xmmEncKey[10]);

    __m128i xmmLs = OcbMulAlpha(xmmL);
    __m128i xmmLd = OcbMulAlpha(xmmLs);

    unsigned char u8NonceBlk[16] = { 0 };
    memcpy(u8NonceBlk, pAesIv, 12);
    u8NonceBlk[15] = 1;
    
    __m128i xmmOffset = _mm_loadu_si128((const __m128i*)u8NonceBlk);
    xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

    __m128i xmmChecksum = _mm_setzero_si128();
    unsigned __int64 uIndex = 0;

    while (uIndex + 16 <= uCipherTextSize) 
    {
        
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLd);

        __m128i xmmCT = _mm_loadu_si128((const __m128i*)(pCipherText + uIndex));
        __m128i xmmY = _mm_xor_si128(xmmCT, xmmOffset);
        __m128i xmmX = _mm_xor_si128(xmmY, xmmDecKey[0]);

        for (int iRound = 1; iRound < 10; ++iRound) {
            xmmX = _mm_aesdec_si128(xmmX, xmmDecKey[iRound]);
        }
        xmmX = _mm_aesdeclast_si128(xmmX, xmmDecKey[10]);

        __m128i xmmPT = _mm_xor_si128(xmmX, xmmOffset);
        _mm_storeu_si128((__m128i*)(pPlainText + uIndex), xmmPT);

        xmmChecksum = _mm_xor_si128(xmmChecksum, xmmPT);
        uIndex += 16;
    }

    if (uIndex < uCipherTextSize) 
    {
        
        unsigned int uLeft = (unsigned int)(uCipherTextSize - uIndex);
        xmmOffset = _mm_xor_si128(xmmOffset, xmmLs);

        __m128i xmmPad = _mm_xor_si128(xmmOffset, xmmEncKey[0]);
        
        for (int iRound = 1; iRound < 10; ++iRound)
            xmmPad = _mm_aesenc_si128(xmmPad, xmmEncKey[iRound]);
        
        xmmPad = _mm_aesenclast_si128(xmmPad, xmmEncKey[10]);

        unsigned char u8Pad[16];
        _mm_storeu_si128((__m128i*)u8Pad, xmmPad);

        unsigned char u8Tail[16] = { 0 };
        
        for (unsigned int j = 0; j < uLeft; ++j) 
        {
            unsigned char p = pCipherText[uIndex + j] ^ u8Pad[j];
            pPlainText[uIndex + j] = p;
            u8Tail[j] = p;
        }

        __m128i xmmTail = _mm_loadu_si128((const __m128i*)u8Tail);
        xmmChecksum = _mm_xor_si128(xmmChecksum, xmmTail);
    }

    __m128i xmmT = _mm_xor_si128(xmmChecksum, _mm_xor_si128(xmmOffset, xmmL));
    __m128i xmmCalcTag = _mm_xor_si128(xmmT, xmmEncKey[0]);
    
    for (int iRound = 1; iRound < 10; ++iRound) 
        xmmCalcTag = _mm_aesenc_si128(xmmCalcTag, xmmEncKey[iRound]);
    
    xmmCalcTag = _mm_aesenclast_si128(xmmCalcTag, xmmEncKey[10]);

    unsigned char u8Expected[16], u8Diff = 0;
    _mm_storeu_si128((__m128i*)u8Expected, xmmCalcTag);
    
    for (int i = 0; i < 16; ++i) 
        u8Diff |= u8Expected[i] ^ pAuthTag[i];

    if (u8Diff != 0) 
    {
        memset(pPlainText, 0, (size_t)uCipherTextSize);                 // Authentication Failed: Clear Output Buffer
        return;
    }

    *pbDecrypted = TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

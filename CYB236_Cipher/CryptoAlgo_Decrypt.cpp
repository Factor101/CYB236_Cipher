#include <cstdint>
#include <iostream>
#include <utility>
#include "CryptoAlgo.h"

std::pair<uint8_t*, size_t> CryptoAlgo::decrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey)
{
    printf("Decrypting ciphertext of %zu bytes\n", msgSizeBytes);

    // allocate memory for decrypted message and copy the ciphertext
    // no padding necessary since the ciphertext is already padded
    uint8_t* decrypted = new uint8_t[msgSizeBytes];
    memcpy(decrypted, msg, msgSizeBytes);

    // Process each block with its corresponding key.
    // We can shift the key the exact same way as in encryption
    const auto nBlocks = msgSizeBytes / BLOCK_SIZE_BYTES;
    uint32_t key = initialKey;
    for (uint64_t i = 0; i < nBlocks; ++i)
    {
        uint8_t* curBlockLocation = decrypted + (i * BLOCK_SIZE_BYTES);
        CryptoAlgo::decryptBlock(curBlockLocation, key);
        key = CryptoAlgo::circularShiftKey(key);
    }

    // TODO: we should trim the padding before returning but whatever
    return std::make_pair(decrypted, msgSizeBytes);
}

void CryptoAlgo::decryptBlock(uint8_t* blockStart, const uint32_t key)
{
    constexpr auto HALF_BLOCK_SIZE_BYTES = BLOCK_SIZE_BYTES / 2ul;
    uint8_t* leftBlock = blockStart;
    uint8_t* rightBlock = blockStart + HALF_BLOCK_SIZE_BYTES;

    // Inverse of encryption: swap left and right halves again
    // Allocate a tmp buffer to hold one half of the block during the swap
    uint8_t* tmp = (uint8_t*)malloc(HALF_BLOCK_SIZE_BYTES);
    if (tmp == nullptr)
    {
        std::cerr << "Failed to allocate memory for block swap in decryptBlock!\n";
        std::exit(-1);  // NOLINT(concurrency-mt-unsafe)
    }

    // Swap left and right halves
    memcpy(tmp, leftBlock, HALF_BLOCK_SIZE_BYTES);
    memcpy(leftBlock, rightBlock, HALF_BLOCK_SIZE_BYTES);
    memcpy(rightBlock, tmp, HALF_BLOCK_SIZE_BYTES);

    // Free the temporary buffer
    free(tmp);

    // Inverse the left side operations
    // Encryption does XOR of left ^= right
    // So to decrypt we need to XOR left with right again
    CryptoAlgo::xorBytes(leftBlock, HALF_BLOCK_SIZE_BYTES, rightBlock);

    // Inverse the right side operations
    // Encryption does right = applySBOX(right XOR key)
    // Decryption: first apply inverse SBOX to right block, then XOR with key.
    CryptoAlgo::applyInverseSBox(rightBlock, HALF_BLOCK_SIZE_BYTES);
    CryptoAlgo::xorBytesWithKey(rightBlock, HALF_BLOCK_SIZE_BYTES, key);
}
#include "CryptoAlgo.h"
#include <iostream>

std::pair<uint8_t*, size_t> CryptoAlgo::encrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey)
{
	printf("Encrypting plaintext of %zu bytes\n", msgSizeBytes);

	// Pad plaintext and get new msg pointer and size
	const std::pair<uint8_t*, size_t> paddedState = CryptoAlgo::padPlaintext(msg, msgSizeBytes);
	uint8_t* state = paddedState.first;
	const size_t paddedStateSize = paddedState.second;

	// we should perform initial permutation here but not defined

	// perform block encryption
	// for each block perform a circular shift by KEYSHIFT_N_BITS
	const auto nBlocks = paddedStateSize / BLOCK_SIZE_BYTES;
	uint32_t key = initialKey;
	for (uint64_t i = 0; i < nBlocks; ++i)
	{
		uint8_t* curBlockLocation = state + (i * BLOCK_SIZE_BYTES);
		CryptoAlgo::encryptBlock(curBlockLocation, key);
		key = CryptoAlgo::circularShiftKey(key);
	}

	return std::make_pair(state, paddedStateSize);
}

void CryptoAlgo::encryptBlock(uint8_t* blockStart, const uint32_t key)
{
	// Split the block into left and right halves of BLOCK_SIZE / 2
	constexpr auto HALF_BLOCK_SIZE_BYTES = BLOCK_SIZE_BYTES / 2ul;
	uint8_t* leftBlock = blockStart;
	uint8_t* rightBlock = blockStart + HALF_BLOCK_SIZE_BYTES;

	// XOR right block with key
	// 32b key is split into 4 8b bytes
	CryptoAlgo::xorBytesWithKey(rightBlock, HALF_BLOCK_SIZE_BYTES, key);

	// diagram says expand to 24 bits but then after SBOX we have 16 bits again
	// so I am ignoring that step

	// Apply S-Box to right block
	CryptoAlgo::applySBox(rightBlock, HALF_BLOCK_SIZE_BYTES);

	// apply "permutation (fp)" (undefined) to right block

	// XOR left block with right block
	CryptoAlgo::xorBytes(leftBlock, HALF_BLOCK_SIZE_BYTES, rightBlock);

	// swap, then write left and right blocks back into blockStart

	// Allocate a tmp buffer to hold one half of the block during the swap
	uint8_t* tmp = (uint8_t*)malloc(HALF_BLOCK_SIZE_BYTES);
	if (tmp == nullptr)
	{
		std::cerr << "Failed to allocate memory for block swap!\n";
		exit(-1); // NOLINT(concurrency-mt-unsafe)
	}

	// Swap left and right blocks
	// Copy left into tmp
	memcpy(tmp, leftBlock, HALF_BLOCK_SIZE_BYTES);
	memcpy(leftBlock, rightBlock, HALF_BLOCK_SIZE_BYTES);
	memcpy(rightBlock, tmp, HALF_BLOCK_SIZE_BYTES);

	// Free tmp buffer
	free(tmp);
}

std::pair<uint8_t*, size_t> CryptoAlgo::padPlaintext(const uint8_t* msg, const size_t msgSizeBytes) noexcept
{
	CryptoAlgo::printMsgBytes(msg, msgSizeBytes);

	// Pad the plaintext to a multiple of the block size
	const auto sizeBits = msgSizeBytes * 8;
	const size_t paddedSizeBytes = sizeBits % BLOCK_SIZE_BITS == 0
		? msgSizeBytes
		: (msgSizeBytes + (BLOCK_SIZE_BITS - sizeBits % BLOCK_SIZE_BITS) / 8);

	// Allocate the padded message and copy the original message into it
	uint8_t* paddedMsg = new uint8_t[paddedSizeBytes];
	memcpy(paddedMsg, msg, msgSizeBytes);
	memset(paddedMsg + msgSizeBytes, 0, paddedSizeBytes - msgSizeBytes);

	printf("Padding plaintext from %zu bytes to %zu bytes\n", msgSizeBytes, paddedSizeBytes);
	std::cout << "Padded plaintext (bytes):\n";
	CryptoAlgo::printMsgBytes(paddedMsg, paddedSizeBytes);

	// Return the padded message and its new size
	return std::make_pair(paddedMsg, paddedSizeBytes);
}
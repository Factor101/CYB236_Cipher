#include "CryptoAlgo.h"

#include <iostream>

#include "rijindael_sbox.h"

uint8_t* CryptoAlgo::padPlaintext(const uint8_t* msg, size_t msgSizeBytes)
{
	// ensure msg bytes % (BLOCK_SIZE_BITS / 8) == 0, and msgSizeBytes >= BLOCK_SIZE_BITS / 8
	if (msgSizeBytes % (BLOCK_SIZE_BITS / 8) == 0)
	{
		return (uint8_t*)msg;
	}

	// pad msg with 0s

}

uint8_t* CryptoAlgo::encrypt(const uint8_t* msg, size_t msgSizeBytes, uint32_t initialKey)
{
	msg = CryptoAlgo::padPlaintext(msg, msgSizeBytes);
	msgSizeBytes = strlen((const char*)msg);

	std::cout << "msg: " << msg << std::endl;
	std::cout << "msg size (bytes): " << msgSizeBytes << std::endl;


	return nullptr;
}

uint8_t* CryptoAlgo::decrypt(const uint8_t* msg, size_t msgSizeBytes, uint32_t initialKey)
{
	return nullptr;
}
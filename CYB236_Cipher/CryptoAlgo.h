#pragma once
#include <cstdint>
#include <string>

class CryptoAlgo
{
private:
	constexpr static uint32_t BLOCK_SIZE_BITS = 32;
	static uint8_t* padPlaintext(const uint8_t* msg, size_t msgSizeBytes);
public:
	static uint8_t* encrypt(const uint8_t* msg, size_t msgSizeBytes, uint32_t initialKey);
	static uint8_t* decrypt(const uint8_t* msg, size_t msgSizeBytes, uint32_t initialKey);
};

#pragma once
#include <cstdint>
#include <string>

class CryptoAlgo
{
private:
	// Encryption Algorithm params
	constexpr static uint32_t BLOCK_SIZE_BITS = 32;
	constexpr static uint32_t BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 4ul;
	constexpr static auto KEYSHIFT_N_BITS = 1;

	// Functionality
	static std::pair<uint8_t*, size_t> padPlaintext(const uint8_t* msg, const size_t msgSizeBytes);
	static void encryptBlock(uint8_t* blockStart, const uint32_t key);
	static void xorBytes(uint8_t* bytes, const size_t nBytes, const uint8_t* operandBytes);
	static void xorBytesWithKey(uint8_t* bytes, const size_t nBytes, const uint32_t key);
	static void applySBox(uint8_t* bytes, const size_t nBytes);
public:
	static void printMsgBytes(const uint8_t* msg, const size_t msgSizeBytes);
	static std::pair<uint8_t*, size_t> encrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey);
	static std::pair<uint8_t*, size_t> decrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey);
};
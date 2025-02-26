#pragma once
#include <cstdint>
#include <string>

class CryptoAlgo
{
private:
	constexpr static uint32_t BLOCK_SIZE_BITS = 32;
	constexpr static uint32_t BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 4ul;
	static std::pair<uint8_t*, size_t> padPlaintext(const uint8_t* msg, const size_t msgSizeBytes);
	static void encryptBlock(uint8_t* blockStart, const uint32_t key);
	static void xorBytes(uint8_t* bytes, const size_t nBytes, const uint8_t* operandBytes);
	static void xorBytesWithKey(uint8_t* bytes, const size_t nBytes, const uint32_t key);
	static void applySBox(uint8_t* bytes, const size_t nBytes);
	static void printMsgBytes(const uint8_t* msg, const size_t msgSizeBytes);
public:
	static uint8_t* encrypt(const uint8_t* msg, const size_t msgSizeBytes, uint32_t initialKey);
	static uint8_t* decrypt(const uint8_t* msg, const size_t msgSizeBytes, uint32_t initialKey);
};
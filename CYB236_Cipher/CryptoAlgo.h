#pragma once
#include <cstdint>
#include <string>

class CryptoAlgo
{
private:
	// Encryption Algorithm parameters
	constexpr static uint32_t BLOCK_SIZE_BITS = 32;
	constexpr static uint32_t BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 4ul;
	constexpr static auto KEYSHIFT_N_BITS = 3;

	// General internal utility methods
	static void xorBytes(uint8_t* bytes, const size_t nBytes, const uint8_t* operandBytes) noexcept;
	static void xorBytesWithKey(uint8_t* bytes, const size_t nBytes, const uint32_t key) noexcept;
	static uint32_t circularShiftKey(const uint32_t key) noexcept;
	static void applySBox(uint8_t* bytes, const size_t nBytes) noexcept;
	static void applyInverseSBox(uint8_t* bytes, const size_t nBytes) noexcept;

	// Encryption utility methods
	static std::pair<uint8_t*, size_t> padPlaintext(const uint8_t* msg, const size_t msgSizeBytes) noexcept;
	static void encryptBlock(uint8_t* blockStart, const uint32_t key);

	// Decryption utility methods
	static void decryptBlock(uint8_t* blockStart, const uint32_t key);
public:
	// Main methods for	encryption/decryption
	static std::pair<uint8_t*, size_t> encrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey);
	static std::pair<uint8_t*, size_t> decrypt(const uint8_t* msg, const size_t msgSizeBytes, const uint32_t initialKey);

	// Generic utility functions
	static void printMsgBytes(const uint8_t* msg, const size_t msgSizeBytes) noexcept;
	static void printMsgBits(const uint8_t* msg, size_t msgSizeBytes) noexcept;
};
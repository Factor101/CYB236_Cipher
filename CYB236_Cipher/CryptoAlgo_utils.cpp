#include <iomanip>
#include <iostream>
#include <bitset>
#include "CryptoAlgo.h"
#include "rijindael_sbox.h"

void CryptoAlgo::xorBytes(uint8_t* bytes, const size_t nBytes, const uint8_t* operandBytes) noexcept
{
	for(size_t i = 0; i < nBytes; ++i)
	{
		bytes[i] ^= operandBytes[i];
	}
}

void CryptoAlgo::xorBytesWithKey(uint8_t* bytes, const size_t nBytes, const uint32_t key) noexcept
{
	// XOR each byte w/ the corresponding byte of the key
	// Key is right shifted by (i * 8) bits to get the correct byte
	// Finally mask (& 0xFF) to get only the last 8 bits of the 32b key
	for (size_t i = 0; i < nBytes; ++i)
	{
		bytes[i] ^= (key >> (i * 8)) & 0xFF;
	}
}

/**
 * 
 * @param key A 32 bit unsigned integer
 * @return key circularly bit-shifted left by CryptoAlgo::KEYSHIFT_N_BITS
 */
uint32_t CryptoAlgo::circularShiftKey(const uint32_t key) noexcept
{
	/**
	 * How the circular bit shift works:
	 * 1. Shift the key left by KEYSHIFT_N_BITS
	 * 2. Seperately shift the same original key right by (sizeof(key) * 8u - KEYSHIFT_N_BITS)
	 *		- where sizeof(key) * 8u is the number of bits in the key
	 * 3. Return the bitwise OR | of the result of steps one (lhs) and two (rhs).
	 *
	 * Example with KEYSHIFT_N_BITS = 3 bits and sizeof(key) = 1 Byte:
	 * - Let initKey = 1011'0010 // initial key
	 * - Perform one circular shift:
	 * 		1. Let lhs = initKey << KEYSHIFT_N_BITS bits
	 * 				   = 1011'0010 << 3 = 1001'0000
	 *		2. Let rhs = initKey >> (sizeof(key) * 8u) - KEYSHIFT_N_BITS bits
	 *				   = 1011'0010 >> 5 = 0000'0101
	 *		3. Now return lhs | rhs
	 *			lhs 1001'0000
	 *			rhs 0000'0101 OR
	 *			  = 1001'0101
	 * - Now we can set our key to the result value of 1001'0101.
	 */
	return (key << CryptoAlgo::KEYSHIFT_N_BITS) | (key >> (sizeof(key) * 8u - CryptoAlgo::KEYSHIFT_N_BITS));
}


void CryptoAlgo::applySBox(uint8_t* bytes, const size_t nBytes) noexcept
{
	// Apply S-Box to each byte of the right block
	for(size_t i = 0; i < nBytes; ++i)
	{
		bytes[i] = SBOX[bytes[i]];
	}
}

void CryptoAlgo::applyInverseSBox(uint8_t* bytes, const size_t nBytes) noexcept
{
	// Apply Inverse S-Box to each byte of the right block
	for(size_t i = 0; i < nBytes; ++i)
	{
		bytes[i] = SBOX_INVERSE[bytes[i]];
	}
}

void CryptoAlgo::printMsgBytes(const uint8_t* msg, const size_t msgSizeBytes) noexcept
{
	for(size_t i = 0; i < msgSizeBytes; ++i)
	{
		std::cout << std::hex << "0x" << std::setw(2) << std::setfill('0') << (int)msg[i] << " ";
	}
	std::cout << std::endl << std::dec;
}

void CryptoAlgo::printMsgBits(const uint8_t* msg, const size_t msgSizeBytes) noexcept
{
	for (size_t i = 0; i < msgSizeBytes; ++i)
	{
		// print byte number in hex and then the byte in binary and a newline
		std::cout << std::hex << "0x" << std::setw(2) << std::setfill('0') << (int)i << ": " << std::bitset<8>(msg[i]) << "\n";
	}

	std::cout << std::endl << std::dec;
}
#include <iostream>
#include "CryptoAlgo.h"


int main(int argc, char** argv)
{
    constexpr uint32_t KEY = 0b0101'1011'0101'1101'1110'0010'1010'0001;
    const uint8_t* MSG = (const uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    const size_t MSG_LENGTH = strlen((const char*)MSG);
    const uint64_t MSG_BITS = 8 * MSG_LENGTH;

	const std::pair<uint8_t*, size_t> ciphertext = CryptoAlgo::encrypt(MSG, MSG_LENGTH, KEY);
	std::cout << std::endl << "Ciphertext:\n";
	CryptoAlgo::printMsgBytes(ciphertext.first, ciphertext.second);
	for (size_t i = 0; i < ciphertext.second; ++i)
	{
		std::cout << ciphertext.first[i];
	}
}
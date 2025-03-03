#include <iostream>
#include "CryptoAlgo.h"
#include <bitset>


int main(int argc, char** argv)
{
    // Define the key and message
    constexpr uint32_t KEY = 0b0101'1011'0101'1101'1110'0010'1010'0001;
    //const uint8_t* MSG = (const uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    const uint8_t * MSG = (const uint8_t*)"Peace to the crews from New York to LA, power to the people that struggle everyday";
    const size_t MSG_LENGTH = strlen((const char*)MSG);
    const uint64_t MSG_BITS = 8 * MSG_LENGTH;

    // Encrypt the message
    const std::pair<uint8_t*, size_t> ciphertext = CryptoAlgo::encrypt(MSG, MSG_LENGTH, KEY);

    // Print the ciphertext bytes and bits
    std::cout << std::endl << "Ciphertext:\n Bytes:\n";
    CryptoAlgo::printMsgBytes(ciphertext.first, ciphertext.second);

    std::cout << std::endl << "Bits:\n";
    CryptoAlgo::printMsgBits(ciphertext.first, ciphertext.second);

    // Now decrypt the ciphertext
    const std::pair<uint8_t*, size_t> plaintext = CryptoAlgo::decrypt(ciphertext.first, ciphertext.second, KEY);

    // Print the decrypted plaintext bytes and bits
    std::cout << std::endl << "Plaintext:\n Bytes:\n";
    CryptoAlgo::printMsgBytes(plaintext.first, plaintext.second);

    std::cout << std::endl << "Bits:\n";
    CryptoAlgo::printMsgBits(plaintext.first, plaintext.second);

    // Print the plaintext as ASCII
    std::cout << std::endl << "Plaintext:\n";
    for (size_t i = 0; i < plaintext.second; ++i)
    {
        std::cout << plaintext.first[i];
    }

    // assert that the decrypted plaintext is the same as the original message
    // (technically the decrypted plaintext should be the same as the original message)
    // (however we are not yet trimming the padding on the decrypted plaintext)
    // Should still be the same as the original message up to MSG_LENGTH bytes
    if (memcmp(MSG, plaintext.first, MSG_LENGTH) == 0)
    {
        std::cout << "\n\nDecrypted plaintext matches original message!\n";
    }
    else
    {
        std::cout << "\n\nDecrypted plaintext does NOT match original message!\n";
    }

    // Free allocated memory
    delete[] ciphertext.first;
    delete[] plaintext.first;
    return 0;
}
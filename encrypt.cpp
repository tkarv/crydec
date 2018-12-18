#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include <fstream>
#include <iostream>
#include <iomanip>

int main(int argc, char ** argv) {

    if(argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_unencrypted_file> <input_key_file> <output_encrypted_file>" << std::endl;
        exit(0);
    }

    std::ifstream inf(argv[2]);
    std::string keyiv;
    inf >> keyiv;
    CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);

    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    unsigned int c;
    for(int j=0;j<CryptoPP::AES::DEFAULT_KEYLENGTH;j++) {
        std::string subs = keyiv.substr(j*2, 2);
        key[j] = strtol(subs.c_str(), NULL, 16);
    }
    for(int j=0;j<CryptoPP::AES::DEFAULT_KEYLENGTH;j++) {
        std::string subs = keyiv.substr(CryptoPP::AES::DEFAULT_KEYLENGTH*2 + j*2, 2);
        iv[j] = strtol(subs.c_str(), NULL, 16);
    }

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::FileSource fsource (argv[1],
            true,
            new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::FileSink(argv[3], true)),
            true);


    fsource.PumpAll();

    return 0;

}
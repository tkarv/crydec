#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include <fstream>
#include <iostream>
#include <iomanip>

int main(int argc, char ** argv) {

    if(argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output_key_file>" << std::endl;
        exit(0);
    }
    
    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock( key, key.size() );

    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, iv.size());

    std::ofstream out(argv[3]);
    for(int j=0;j<CryptoPP::AES::DEFAULT_KEYLENGTH;j++) {
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[j]);
    }

    for(int j=0;j<CryptoPP::AES::BLOCKSIZE;j++) {
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(iv[j]);
    }

    out.close();

    return 0;

}
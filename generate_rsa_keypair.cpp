#include <iostream>

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>

void SavePrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key);
void SavePublicKey(const std::string& filename, const CryptoPP::PublicKey& key);
void Save(const std::string& filename, const CryptoPP::BufferedTransformation& bt);

int main(int argc, char ** argv) {
    using namespace CryptoPP;
    if(argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <output_private_key> <output_public_key>" << std::endl;
        exit(0);
    }

    AutoSeededRandomPool rnd;

    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rnd, 4096);

    RSA::PrivateKey privateKey(params);
    privateKey.GenerateRandomWithKeySize(rnd, 4096);

    RSA::PublicKey publicKey(privateKey);

    SavePrivateKey(argv[1], privateKey);
    SavePublicKey(argv[2], publicKey);

    return 0;
}

void SavePrivateKey(const std::string& filename, const CryptoPP::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const std::string& filename, const CryptoPP::PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const std::string& filename, const CryptoPP::BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	CryptoPP::FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

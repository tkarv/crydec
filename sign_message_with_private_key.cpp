#include <iostream>
#include <sstream>

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

void LoadPrivateKey(const std::string& filename, PrivateKey& key);
void LoadPublicKey(const std::string& filename, PublicKey& key);
void Load(const std::string& filename, BufferedTransformation& bt);

void SaveSignature(const std::string filename, const std::string &message);
int main(int argc, char ** argv) {
    if(argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_private_key> <input_message> <output_signature>" << std::endl;
        exit(0);
    }

    AutoSeededRandomPool rnd;

    RSA::PrivateKey privateKey;
    LoadPrivateKey(argv[1], privateKey);

    std::string message, signature;
    std::stringstream ss;

    std::ifstream inf(argv[2]);
    ss << inf.rdbuf();

    message = ss.str();

    std::cout << "message: " << message << std::endl;

    RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

    StringSource ss1(message, true, new SignerFilter(rnd, signer, new StringSink(signature)));

    std::cout << "signature: " << signature << std::endl;

    //std::ofstream ouf(argv[3]);
    SaveSignature(argv[3], signature);

    return 0;
}

void LoadPrivateKey(const std::string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const std::string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const std::string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void SaveSignature(const std::string filename, const std::string &signature) {
    StringSource ss(signature, true, new FileSink(filename.c_str()));
}
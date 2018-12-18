#include <iostream>
#include <sstream>

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

void LoadPrivateKey(const std::string& filename, PrivateKey& key);
void LoadPublicKey(const std::string& filename, PublicKey& key);
void LoadSignature(const std::string& filename, std::string &sig);
void Load(const std::string& filename, BufferedTransformation& bt);

int main(int argc, char ** argv) {
    if(argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_public_key> <input_message> <input_signature>" << std::endl;
        exit(0);
    }

    AutoSeededRandomPool rnd;

    RSA::PublicKey publicKey;
    LoadPublicKey(argv[1], publicKey);

    std::string message, signature;
    std::stringstream ss;

    std::ifstream inf1(argv[2]);
    ss << inf1.rdbuf();
    message = ss.str();

    LoadSignature(argv[3], signature);    
    std::cout << "message: " << message << std::endl;
    std::cout << "signature: " << signature << std::endl;

    RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

    StringSource ss1(message+signature, true, new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION));

    std::cout << "Verification passed on message" << std::endl;

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

void LoadSignature(const std::string& filename, std::string &sig) {
    FileSource file(filename.c_str(), true, new StringSink(sig));
}

void Load(const std::string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

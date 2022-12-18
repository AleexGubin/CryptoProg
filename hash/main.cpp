#include <cryptopp/cryptlib.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;

int main() {
    string gsm, msg, result, result1;
    FileSource("/home/stud/CryptoProg/hash/test", true, new StringSink(msg));
    msg.resize(msg.size() - 1);
    cout << "Text from file: " << msg << endl;
    HexEncoder encoder(new StringSink(result));
    Weak::MD5 hash;
    hash.Update((const byte*)&msg[0], msg.size());
    gsm.resize(hash.DigestSize());
    hash.Final((byte*)&gsm[0]);
    cout << "HASH: ";
    StringSource(gsm, true, new Redirector(encoder));
    cout << result << "\n\n";
    
    // Блок для проверки работоспособности кода выше:
    HexEncoder encoder1(new StringSink(result1));
    string gsm1, msg1 = "My name is Alexander";
    cout << "Text: " << msg1 << endl;
    hash.Update((const byte*)&msg1[0], msg1.size());
    gsm1.resize(hash.DigestSize());
    hash.Final((byte*)&gsm1[0]);
    cout << "HASH: ";
    StringSource(gsm1, true, new Redirector(encoder1));
    cout << result1 << endl;
    if (result == result1)
        cout << "The test was successful!\n\n";
}

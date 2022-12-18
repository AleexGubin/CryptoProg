#include <cryptopp/cryptlib.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/tiger.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;

int main() {
    string mode, input_file_string, output_file_string, pass;
    cout << "Welcome! Enter working mode(encrypt or decrypt): ";
    cin >> mode;
    if (mode != "encrypt" && mode != "decrypt") {
        cerr << "Invalid working mode" << endl;
        return 1;
    }
    cout << "Enter password: ";
    cin >> pass;
    if(pass.size() < 8) {
        cerr << "Error! Too short password\n";
        return 1;
    }
    for(char c : pass){
        if(c < '!' or c > '~') {
            cout << "Invalid symbol in password" << endl;
            return 1;
        }
    }
    if (mode == "encrypt") {
        cout << "Enter input file(or enter default): ";
        cin >> input_file_string;
        if(input_file_string == "default")
            input_file_string = "/home/stud/CryptoProg/cipher/test";
        ifstream input_check(input_file_string);
        if(input_check.is_open() == 0) {
            cerr << "Invalid input file\n";
            return 1;
        }
        input_check.close();
        
        cout << "Enter output file(or enter default): ";
        cin >> output_file_string;
        if(output_file_string == "default")
            output_file_string = "/home/stud/CryptoProg/cipher/encrypted_text_file";
        ifstream output_check(output_file_string);
        if(output_check.is_open() == 0) {
            cerr << "Invalid output file\n";
            return 1;
        }
        output_check.close();
        
        byte pass_b[pass.size()];
        StringSource(pass, true, new HexEncoder(new ArraySink(pass_b, sizeof(pass_b)))); 
        size_t plen = strlen((const char*)pass_b);
        AutoSeededRandomPool SALT_gen;
        byte SALT[AES::BLOCKSIZE];
        SALT_gen.GenerateBlock(SALT, sizeof(SALT));
        byte key[Tiger::DIGESTSIZE];
        size_t slen = strlen((const char*)SALT);
        PKCS5_PBKDF1<Tiger> key_obj;
        byte unused = 0;
        
        key_obj.DeriveKey(key, sizeof(key), unused, pass_b, plen, SALT, slen, 128, 0.0f);
        AutoSeededRandomPool prng;
        byte IV[ AES::BLOCKSIZE ];
        prng.GenerateBlock(IV, sizeof(IV));
        
        ofstream user_password_file("/home/stud/CryptoProg/cipher/user_password_file");
        StringSource(pass, true, new FileSink(user_password_file));
        ofstream key_file("/home/stud/CryptoProg/cipher/key_file");
        ArraySource(key, sizeof(key), true, new FileSink(key_file));
        ofstream IV_file("/home/stud/CryptoProg/cipher/iv_file");
        ArraySource(IV, sizeof(IV), true, new FileSink(IV_file));
        
        CBC_Mode< AES >::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), IV );
        ifstream input_file(input_file_string);
        ofstream output_file(output_file_string);
        FileSource(input_file, true, new StreamTransformationFilter( encryptor, new FileSink(output_file)));
        input_file.close();
        output_file.close();
        }
    
    else if (mode == "decrypt") {
        string user_pass;
        FileSource("/home/stud/CryptoProg/cipher/user_password_file", true, new StringSink(user_pass));
        if (pass == user_pass) {
            cout << "Invalid password\n";
            return 1;
        }
        cout << "Enter input file(or enter default): ";
        cin >> input_file_string;
        if(input_file_string == "default")
            input_file_string = "/home/stud/CryptoProg/cipher/encrypted_text_file";
        ifstream input_check(input_file_string);
        if(input_check.is_open() == 0) {
            cerr << "Invalid input file" << endl;
            return 1;
        }
        input_check.close();
        
        cout << "Enter output file(or enter default): ";
        cin >> output_file_string;
        if(output_file_string == "default")
            output_file_string = "/home/stud/CryptoProg/cipher/decrypted_text_file";
        ifstream output_check(output_file_string);
        if(output_check.is_open() == 0) {
            cerr << "Invalid output file" << endl;
            return 1;
        }
        output_check.close();
        
        byte key[Tiger::DIGESTSIZE];
        FileSource("/home/stud/CryptoProg/cipher/key_file", true, new ArraySink(key, sizeof(key)));
        byte IV[ AES::BLOCKSIZE ];
        FileSource("/home/stud/CryptoProg/cipher/iv_file", true, new ArraySink(IV, sizeof(IV)));
        
        CBC_Mode< AES >::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), IV);
        ifstream input_file(input_file_string);
        ofstream output_file(output_file_string);
        FileSource(input_file, true, new StreamTransformationFilter( decryptor, new FileSink(output_file)));
        }
    }

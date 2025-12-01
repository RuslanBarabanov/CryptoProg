#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
using namespace std;
using namespace CryptoPP;

const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;  
const int BLOCK_SIZE = AES::BLOCKSIZE;         
const int SALT_SIZE = 8;                    

void DeriveKey(const string& password, byte* key, byte* iv, byte* salt) {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(salt, SALT_SIZE);

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, KEY_SIZE, 0,
                   (byte*)password.data(), password.size(),
                   salt, SALT_SIZE,
                   10000);  

    string ivPassword = password + "IV";
    PKCS5_PBKDF2_HMAC<SHA256> pbkdfIV;
    pbkdfIV.DeriveKey(iv, BLOCK_SIZE, 0,
                     (byte*)ivPassword.data(), ivPassword.size(),
                     salt, SALT_SIZE,
                     10000);
}

void EncryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        byte key[KEY_SIZE];
        byte iv[BLOCK_SIZE];
        byte salt[SALT_SIZE];

        DeriveKey(password, key, iv, salt);

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, KEY_SIZE, iv);

        FileSource(inputFile.c_str(), true,
            new StreamTransformationFilter(encryptor,
                new FileSink(outputFile.c_str(), true)
            )
        );
        
        fstream fout(outputFile.c_str(), ios::binary | ios::in | ios::out);
        if (!fout) {
            throw runtime_error("Не удалось открыть выходной файл для записи соли");
        }

        fout.seekg(0, ios::end);
        streamsize size = fout.tellg();
        fout.seekg(0, ios::beg);
        
        byte* encryptedData = new byte[size];
        fout.read((char*)encryptedData, size);
        fout.close();
        
        fout.open(outputFile.c_str(), ios::binary | ios::out);
        fout.write((char*)salt, SALT_SIZE);
        fout.write((char*)encryptedData, size);
        fout.close();
        
        delete[] encryptedData;
        
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error(string("Ошибка шифрования: ") + e.what());
    }
}

void DecryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        ifstream fin(inputFile.c_str(), ios::binary | ios::ate);
        if (!fin) {
            throw runtime_error("Не удалось открыть входной файл");
        }
        
        streamsize size = fin.tellg();
        fin.seekg(0, ios::beg);
        
        if (size <= SALT_SIZE) {
            throw runtime_error("Файл слишком мал для расшифрования");
        }
        
        byte salt[SALT_SIZE];
        fin.read((char*)salt, SALT_SIZE);
        
        streamsize encryptedSize = size - SALT_SIZE;
        byte* encryptedData = new byte[encryptedSize];
        fin.read((char*)encryptedData, encryptedSize);
        fin.close();

        byte key[KEY_SIZE];
        byte iv[BLOCK_SIZE];
        
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
        pbkdf.DeriveKey(key, KEY_SIZE, 0,
                       (byte*)password.data(), password.size(),
                       salt, SALT_SIZE,
                       10000);
        
        string ivPassword = password + "IV";
        PKCS5_PBKDF2_HMAC<SHA256> pbkdfIV;
        pbkdfIV.DeriveKey(iv, BLOCK_SIZE, 0,
                         (byte*)ivPassword.data(), ivPassword.size(),
                         salt, SALT_SIZE,
                         10000);
        
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, KEY_SIZE, iv);
        
        string decryptedData;
        ArraySource(encryptedData, encryptedSize, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedData)
            )
        );

        ofstream fout(outputFile.c_str(), ios::binary);
        fout.write(decryptedData.c_str(), decryptedData.size());
        fout.close();
        
        delete[] encryptedData;
        
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error(string("Ошибка расшифрования: ") + e.what());
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cout << "Использование: " << endl;
        cout << "  Шифрование: " << argv[0] << " enc <входной_файл> <выходной_файл> <пароль>" << endl;
        cout << "  Расшифрование: " << argv[0] << " dec <входной_файл> <выходной_файл> <пароль>" << endl;
        return 1;
    }
    
    string mode = argv[1];
    string inputFile = argv[2];
    string outputFile = argv[3];
    string password = argv[4];
    
    ifstream test(inputFile.c_str());
    if (!test) {
        cerr << "Ошибка: входной файл не найден" << endl;
        return 1;
    }
    test.close();
    
    try {
        if (mode == "enc") {
            EncryptFile(inputFile, outputFile, password);
            cout << "Файл зашифрован: " << outputFile << endl;
        } 
        else if (mode == "dec") {
            DecryptFile(inputFile, outputFile, password);
            cout << "Файл расшифрован: " << outputFile << endl;
        }
        else {
            cerr << "Неверный режим. Используйте 'enc' или 'dec'" << endl;
            return 1;
        }
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        if (mode == "dec") {
            cerr << "Возможно, неправильный пароль или файл поврежден" << endl;
        }
        return 1;
    }
    
    return 0;
}
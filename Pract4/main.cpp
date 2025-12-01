#include <iostream>
#include <fstream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Использование: " << argv[0] << " <имя_файла>" << endl;
        return 1;
    }

    string filename = argv[1];
    
    ifstream fileTest(filename.c_str());
    if (!fileTest.good()) {
        cerr << "Ошибка: файл не найден" << endl;
        return 1;
    }
    fileTest.close();
    
    try {
        SHA256 hash;
        string digest;
        
        // Чтение файла и вычисление хэша
        FileSource file(filename.c_str(), true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        
        cout << digest << endl;
        
    } catch (const Exception& e) {
        cerr << "Ошибка Crypto++: " << e.what() << endl;
        return 1;
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
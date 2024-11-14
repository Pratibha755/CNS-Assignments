#include <iostream>
#include <string>

using namespace std;

// Function to encrypt using Caesar Cipher
string caesarEncrypt(string text, int key) {
    string result = "";

    // Traverse each character in the input text
    for (int i = 0; i < text.length(); i++) {
        char c = text[i];

        // Encrypt uppercase letters
        if (isupper(c)) {
            result += char(int(c + key - 65) % 26 + 65);
        }
        // Encrypt lowercase letters
        else if (islower(c)) {
            result += char(int(c + key - 97) % 26 + 97);
        } else {
            // Non-alphabetical characters remain unchanged
            result += c;
        }
    }
    return result;
}

// Function to decrypt using Caesar Cipher
string caesarDecrypt(string cipherText, int key) {
    string result = "";

    // Traverse each character in the cipher text
    for (int i = 0; i < cipherText.length(); i++) {
        char c = cipherText[i];

        // Decrypt uppercase letters
        if (isupper(c)) {
            result += char(int(c - key - 65 + 26) % 26 + 65);
        }
        // Decrypt lowercase letters
        else if (islower(c)) {
            result += char(int(c - key - 97 + 26) % 26 + 97);
        } else {
            // Non-alphabetical characters remain unchanged
            result += c;
        }
    }
    return result;
}

int main() {
    string text;
    int key;

    // Input the message to encrypt
    cout << "Enter the message: ";
    getline(cin, text);

    // Input the key (number of shifts)
    cout << "Enter the key (shift value): ";
    cin >> key;

    // Encrypt the message
    string cipherText = caesarEncrypt(text, key);
    cout << "Encrypted message: " << cipherText << endl;

    // Decrypt the message
    string decryptedText = caesarDecrypt(cipherText, key);
    cout << "Decrypted message: " << decryptedText << endl;

    return 0;
}

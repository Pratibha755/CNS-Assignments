#include <iostream>
#include <vector>
#include <string>
using namespace std;

// Function to convert a character to an integer (A=0, B=1, ..., Z=25)
int charToInt(char c) {
    return (toupper(c) - 'A');
}

// Function to convert an integer to a character (0=A, 1=B, ..., 25=Z)
char intToChar(int n) {
    return (n % 26) + 'A';
}

// Function to convert a string key into a 3x3 matrix
vector<vector<int>> keyToMatrix(string key) {
    vector<vector<int>> matrix(3, vector<int>(3));
    int k = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            matrix[i][j] = charToInt(key[k++]);
        }
    }
    return matrix;
}

// Function to encrypt using Hill Cipher with 3x3 key matrix
string hillCipherEncrypt(string plaintext, vector<vector<int>> key) {
    string ciphertext = "";

    // Ensure the plaintext length is a multiple of 3 by adding filler characters (e.g., 'X')
    while (plaintext.length() % 3 != 0) {
        plaintext += 'X';
    }

    // Encrypt each block of 3 characters
    for (int i = 0; i < plaintext.length(); i += 3) {
        // Convert the characters to integers
        int p1 = charToInt(plaintext[i]);
        int p2 = charToInt(plaintext[i + 1]);
        int p3 = charToInt(plaintext[i + 2]);

        // Multiply the key matrix with the plaintext vector
        int c1 = (key[0][0] * p1 + key[0][1] * p2 + key[0][2] * p3) % 26;
        int c2 = (key[1][0] * p1 + key[1][1] * p2 + key[1][2] * p3) % 26;
        int c3 = (key[2][0] * p1 + key[2][1] * p2 + key[2][2] * p3) % 26;

        // Convert the results back to characters
        ciphertext += intToChar(c1);
        ciphertext += intToChar(c2);
        ciphertext += intToChar(c3);
    }

    return ciphertext;
}

int main() {
    string plaintext, key;

    // Input the plaintext
    cout << "Enter the plaintext (3 letters): ";
    cin >> plaintext;

    // Input the key as a string (9 letters for 3x3 matrix)
    cout << "Enter the 9-letter key: ";
    cin >> key;

    // Convert the key string to a 3x3 matrix
    vector<vector<int>> keyMatrix = keyToMatrix(key);

    // Encrypt the plaintext using the provided key matrix
    string encryptedText = hillCipherEncrypt(plaintext, keyMatrix);
    cout << "Encrypted Text: " << encryptedText << endl;

    return 0;
}

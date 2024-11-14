#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

// Function to encrypt the plain text using single columnar transposition
string encrypt(string plainText, string key) {
    int row = (plainText.length() + key.length() - 1) / key.length();  // Calculate the number of rows
    vector<vector<char>> matrix(row, vector<char>(key.length(), '_'));  // Create a matrix
    
    // Fill the matrix with the plain text
    int index = 0;
    for (int i = 0; i < row; i++) {
        for (int j = 0; j < key.length(); j++) {
            if (index < plainText.length()) {
                matrix[i][j] = plainText[index++];
            }
        }
    }

    // Sort the key to get the order of columns
    string sortedKey = key;
    sort(sortedKey.begin(), sortedKey.end());

    // Generate the cipher text by reading columns based on sorted key order
    string cipherText = "";
    for (char ch : sortedKey) {
        int col = key.find(ch);  // Find the column for the current key character
        for (int i = 0; i < row; i++) {
            cipherText += matrix[i][col];
        }
    }

    return cipherText;
}

// Function to perform double columnar transposition
string doubleColumnarTransposition(string plainText, string key1, string key2) {
    // First encryption using the first key
    string intermediateCipher = encrypt(plainText, key1);
    // Second encryption using the second key
    string finalCipher = encrypt(intermediateCipher, key2);
    return finalCipher;
}

int main() {
    string plainText, key1, key2;

    cout << "Enter the plain text: ";
    getline(cin, plainText);
    cout << "Enter the first key: ";
    getline(cin, key1);
    cout << "Enter the second key: ";
    getline(cin, key2);

    // Encrypt the plain text with double columnar transposition
    string cipherText = doubleColumnarTransposition(plainText, key1, key2);
    cout << "Encrypted text: " << cipherText << endl;

    return 0;
}

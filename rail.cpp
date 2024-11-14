#include <iostream>
#include <string>
using namespace std;

// Rail Fence cipher
string encryptRailFence(string text, int key) {
    // Create a 2D array to simulate the rail matrix
    char rail[key][text.length()];
    
    // Fill the rail matrix with null characters
    for (int i = 0; i < key; i++)
        for (int j = 0; j < text.length(); j++)
            rail[i][j] = '\n';

    // Set direction to down initially
    bool dir_down = false;
    int row = 0, col = 0;

    // Place the text characters in the matrix in zigzag
    for (int i = 0; i < text.length(); i++) {
        // Check direction and place the character
        if (row == 0 || row == key - 1) // CHECK if First row or last row
            dir_down = !dir_down;

        rail[row][col++] = text[i];

        // Update row number based on direction
        dir_down ? row++ : row--;
    }

    // Construct the cipher text by reading the matrix row by row
    string result;
    for (int i = 0; i < key; i++)
        for (int j = 0; j < text.length(); j++)
            if (rail[i][j] != '\n')
                result.push_back(rail[i][j]);

    return result;
}

int main() {
    string text;
    int key;

    cout << "Enter the text to encrypt: ";
    getline(cin, text);

    cout << "Enter the key (number of rails): ";
    cin >> key;

    string encryptedText = encryptRailFence(text, key);
    cout << "Encrypted Text: " << encryptedText <<endl;

    return 0;
}

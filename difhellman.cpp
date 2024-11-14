#include <iostream>
#include <cmath>
#include <string>

using namespace std;

// Function to calculate (base^exp) % mod using modular exponentiation
long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;  // Reduce base modulo mod

    while (exp > 0) {
        if (exp % 2 == 1)  // If exp is odd, multiply base with result
            result = (result * base) % mod;
        exp = exp >> 1;    // Divide the exponent by 2
        base = (base * base) % mod;  // Square the base
    }

    return result;
}

// Function to XOR encrypt/decrypt the message using the shared key
string xorEncryptDecrypt(const string& message, long long key) {
    string result = message;
    for (size_t i = 0; i < message.length(); i++) {
        result[i] = message[i] ^ (key % 256);  // XOR each character with the key (mod 256 to keep within byte range)
    }
    return result;
}

int main() {
    long long prime = 23, primitiveRoot = 5, privateKeyAlice = 6, privateKeyBob = 15;
    
    // Display the message-based input values
    cout << "Message:\n";
    cout << "Prime (P): " << prime << endl;
    cout << "Primitive Root (G): " << primitiveRoot << endl;
    cout << "Alice's Private Key: " << privateKeyAlice << endl;
    cout << "Bob's Private Key: " << privateKeyBob << endl;

    // Calculate public keys
    long long publicKeyAlice = modExp(primitiveRoot, privateKeyAlice, prime);  // G^a % P
    long long publicKeyBob = modExp(primitiveRoot, privateKeyBob, prime);      // G^b % P

    cout << "\nPublic keys exchanged over the network:\n";
    cout << "Alice's Public Key: " << publicKeyAlice << endl;
    cout << "Bob's Public Key: " << publicKeyBob << endl;

    // Calculate shared secret keys
    long long sharedSecretAlice = modExp(publicKeyBob, privateKeyAlice, prime);  // (G^b)^a % P
    long long sharedSecretBob = modExp(publicKeyAlice, privateKeyBob, prime);    // (G^a)^b % P

    // If the keys match, the shared secret is correct
    if (sharedSecretAlice == sharedSecretBob) {
        cout << "\nKey exchange successful! Shared secret: " << sharedSecretAlice << endl;
    } else {
        cout << "\nKey exchange failed! Keys do not match." << endl;
        return 0;
    }

    // Ask the user for a message to encrypt
    string message;
    cout << "\nEnter a message to encrypt: ";
    getline(cin, message);

    // Encrypt the message using XOR encryption with the shared secret
    string encryptedMessage = xorEncryptDecrypt(message, sharedSecretAlice);
    cout << "\nEncrypted message: " << encryptedMessage << endl;

    // Decrypt the message using XOR encryption (same process as encryption)
    string decryptedMessage = xorEncryptDecrypt(encryptedMessage, sharedSecretAlice);
    cout << "Decrypted message: " << decryptedMessage << endl;

    return 0;
}

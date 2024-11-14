#include <iostream>
#include <cmath>
#include <string>

using namespace std;

// Function to calculate (base^exp) % mod using modular exponentiation
long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;

    while (exp > 0) {
        if (exp % 2 == 1) {  // If exp is odd, multiply base with result
            result = (result * base) % mod;
        }
        exp = exp >> 1;  // Divide the exponent by 2
        base = (base * base) % mod;  // Square the base
    }
    return result;
}

// Function to calculate gcd of two numbers
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to find modular inverse using the extended Euclidean algorithm
long long modInverse(long long e, long long phi) {
    long long t = 0, newt = 1;
    long long r = phi, newr = e;

    while (newr != 0) {
        long long quotient = r / newr;
        t = t - quotient * newt;
        swap(t, newt);
        r = r - quotient * newr;
        swap(r, newr);
    }

    if (r > 1) return -1;  // No modular inverse
    if (t < 0) t = t + phi;
    return t;
}

int main() {
    // Step 1: Input two prime numbers from the user
    long long p, q;
    cout << "Enter prime number p: ";
    cin >> p;
    cout << "Enter prime number q: ";
    cin >> q;

    // Step 2: Compute n = p * q and φ(n) = (p-1)*(q-1)
    long long n = p * q;
    long long phi = (p - 1) * (q - 1);

    // Step 3: Choose a public exponent e such that gcd(e, φ(n)) = 1
    long long e = 2;
    while (gcd(e, phi) != 1) {
        e++;  // Increment e until gcd(e, φ(n)) = 1
    }

    // Step 4: Compute the private key d (modular inverse of e mod φ(n))
    long long d = modInverse(e, phi);
    if (d == -1) {
        cout << "Modular inverse of e does not exist!" << endl;
        return 0;
    }

    cout << "Public Key: (" << e << ", " << n << ")" << endl;
    cout << "Private Key: (" << d << ", " << n << ")" << endl;

    // Step 5: Input the message to be encrypted
    string message;
    cout << "Enter a message to encrypt (a single number): ";
    cin >> message;

    // Convert the message to an integer (for simplicity, we assume the message is a number)
    long long M = stoll(message);  // Convert message to a number

    // Step 6: Encrypt the message
    long long C = modExp(M, e, n);  // C = M^e mod n
    cout << "Encrypted message: " << C << endl;

    // Step 7: Decrypt the ciphertext
    long long decryptedMessage = modExp(C, d, n);  // M = C^d mod n
    cout << "Decrypted message: " << decryptedMessage << endl;

    return 0;
}

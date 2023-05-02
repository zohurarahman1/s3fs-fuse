#include <string.h>
#include <stdio.h>
#include <stdlib.h>

class RC4 {
private:
    unsigned char s_box[256];
    int prga_index_a;
    int prga_index_b;
    int key_size;

    // Swap function used by ksa
    void swap(unsigned char data[], int i, int j) {
        unsigned char temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }

    // Key-scheduling
    void ksa(unsigned char *key, int size) {
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s_box[i] + key[i % size]) % 256;
            swap(s_box, i, j);
        }
    }

    // Pseudo-random generation for encryption
    void prga(unsigned char *plaintext, unsigned char *ciphertext, int size) {
        for (int k = 0; k < size; k++) {
            prga_index_a = (prga_index_a + 1) % 256;
            prga_index_b = (prga_index_b + s_box[prga_index_a]) % 256;
            swap(s_box, prga_index_a, prga_index_b);
            ciphertext[k] = s_box[(s_box[prga_index_a] + s_box[prga_index_b]) % 256] ^ plaintext[k];
        }
    }

    // PRGA to handle plaintext and ciphertext as char arrays
    void prga(char *plaintext, char *cipher, int size) {
        prga((unsigned char *) plaintext, (unsigned char *) cipher, size);
    }

public:
    RC4() {
        prga_index_a = 0;
        prga_index_b = 0;
        key_size = 0;
        memset(s_box, 0, sizeof(s_box));
    }

    // Set the secret key for RC4 encryption
    void set_key(unsigned char *key, int size) {
        prga_index_a = 0;
        prga_index_b = 0;
        key_size = size;
        for (int i = 0; i < 256; i++) {
            s_box[i] = (unsigned char)i;
        }
        ksa(key, size);
    }

    // Encrypt plaintext and store result in the ciphertext char array
    void encrypt(char *plaintext, char *ciphertext, int size) {
        prga(plaintext, ciphertext, size);
    }

    // Encrypt to handle plaintext and ciphertext as char arrays
    void encrypt(unsigned char *plaintext, unsigned char *ciphertext, int size) {
        prga(plaintext, ciphertext, size);
    }
};

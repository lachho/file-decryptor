////////////////////////////////////////////////////////////////////////////////
// COMP1521 23T3 --- Assignment 2: `tide', a terribly insecure (file) decryptor
// <https://www.cse.unsw.edu.au/~cs1521/23T3/assignments/ass2/index.html>
//
// 2023-10-25   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>
// Some useful constants and function signatures for tide.c

#ifndef __TIDE_H__
#define __TIDE_H__

#include <stdbool.h>

// The maximum length of a pathname or filename.
#define MAX_PATH_LEN 4096
// The maximum number of listings possible for a directory, or results for
// a given search.
#define MAX_LISTINGS 512
// The maximum number of bytes that a user could search for.
#define MAX_SEARCH_SIZE 256
// The key for the XOR encryption algorithm.
#define XOR_BYTE_VALUE 0xA9
// The size of a cipher block.
#define CIPHER_BLOCK_SIZE 16
// The size of the initialisation vector.
#define RAND_STR_LEN 16


// Struct used for sorting results of content searching.
typedef struct content_result {
    char *filename;  /* The filename of the result. */
    int matches;     /* The number of matches in the file. */
} content_result;


void print_current_directory(void);
void change_current_directory(char *directory);
void list_current_directory(void);

bool is_encryptable(char *filename);
void xor_file_contents(char *src_filename, char *dest_filename);

void search_by_filename(char *search_string);
void search_by_content(char *search_bytes, int size);

void ecb_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]);
void ecb_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]);

void cbc_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]);
void cbc_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]);

char *shift_encrypt(char  *plaintext, char password[CIPHER_BLOCK_SIZE]);
char *shift_decrypt(char *ciphertext, char password[CIPHER_BLOCK_SIZE]);

void  sort_strings(char *strings[], int count);
void  sort_content_results(content_result *results[], int count);
char *generate_random_string(int seed);

#endif

// This program was written 04/11/2023.

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "decrypt.h"

// Add any extra #defines here.
#define BYTE 8
#define ENCIPHER true
#define DECIPHER false
#define SEED 1

// Add any extra function signatures here.
void print_dir_items(char *items[], int count);
void free_dir_items(char *items[], int count);
void search_dir_by_name(char *items[], char *directory, int *count, 
                        char *search_string);
void search_dir_by_content(content_result *items[], char *directory, int *count, 
                           char *search_bytes, int size);
int count_matches(char *pathname, char *search_bytes, int size);
void ecb_write(char *filename, char password[CIPHER_BLOCK_SIZE], bool shift);
char *read_block(FILE *input);
char *shift_encrypt(char *plaintext, char password[CIPHER_BLOCK_SIZE]);
char *shift_decrypt(char *ciphertext, char password[CIPHER_BLOCK_SIZE]);
uint8_t bit_rotate(int n_rotations, uint8_t bits, bool shift);


// Some provided strings which you may find useful. Do not modify.
const char *const MSG_ERROR_FILE_STAT  = "Could not stat file.\n";
const char *const MSG_ERROR_FILE_OPEN  = "Could not open file.\n";
const char *const MSG_ERROR_CHANGE_DIR = "Could not change directory.\n";
const char *const MSG_ERROR_DIRECTORY  =
    "tide does not support encrypting directories.\n";
const char *const MSG_ERROR_READ       =
    "group does not have permission to read this file.\n";
const char *const MSG_ERROR_WRITE      =
    "group does not have permission to write here.\n";
const char *const MSG_ERROR_RESERVED   =
    "'.' and '..' are reserved filenames, please search for something else.\n";
const char *const MSG_ERROR_SEARCH     = "No search string specified.\n";

/////////////////////////////////// SUBSET 0 ///////////////////////////////////

// Print the name of the current directory.
void print_current_directory(void) {
    char pathname[MAX_PATH_LEN];
    printf("The current directory is: %s\n", getcwd(pathname, sizeof pathname));
}

// Change the current directory to the given pathname.
void change_current_directory(char *directory) {
    // root directory edge case
    if (strcmp(directory, "~") == 0) {
        char *home = getenv("HOME");
        chdir(home);
        printf("Moving to %s\n", home);
    }
    else if (chdir(directory) != 0) {
        printf("%s", MSG_ERROR_CHANGE_DIR);
    } else {
        printf("Moving to %s\n", directory);
    }   
}

// List the contents of the current directory.
void list_current_directory(void) {
    DIR *directory = opendir(".");

    // create an array of strings of name of the contents of the directory
    struct dirent *item;
    int count = 0;
    char *items[MAX_LISTINGS];
    while ((item = readdir(directory)) != NULL) {
        items[count] = strdup(item->d_name);
        count++;
    }
    closedir(directory);

    sort_strings(items, count);
    print_dir_items(items, count);
    free_dir_items(items, count);
}

void print_dir_items(char *items[], int count) {
    for (int i = 0; i < count; i++) {
        struct stat data;
        if (stat(items[i], &data) == -1) {
            printf("%s", MSG_ERROR_FILE_STAT);
            return;
        }

        // check if directory or file
        if (S_ISDIR(data.st_mode)) {
            putchar('d');
        } else {
            putchar('-');
        }

        // checks permissions using a mask
        char permissions[] = "rwxrwxrwx";
        int mask = 0400;
        for (int j = 0; j < 9; j++) {
            if ((data.st_mode & mask) == 0) {
                permissions[j] = '-';
            }
            mask >>= 1;
        }

        printf("%s\t%s\n", permissions, items[i]);

    }
}

void free_dir_items(char *items[], int count) {
    for (int i = 0; i < count; i++) {
        free(items[i]);
    }
}

/////////////////////////////////// SUBSET 1 ///////////////////////////////////

// Check whether the file meets the criteria to be encrypted.
bool is_encryptable(char *filename) {
    struct stat data;
    if (stat(filename, &data) == -1) {
        printf("%s", MSG_ERROR_FILE_STAT);
        return false;
    }
    // check if directory or file
    else if (S_ISDIR(data.st_mode)) {
        printf("%s", MSG_ERROR_DIRECTORY);
        return false;
    }
    else if (!(data.st_mode & S_IRGRP)) {
        printf("%s", MSG_ERROR_READ);
        return false;
    }
    
    // Extract the directory path
    char dir_path[MAX_PATH_LEN];
    strncpy(dir_path, filename, MAX_PATH_LEN);
    char *last_slash = strrchr(dir_path, '/');

    if (last_slash != NULL) {
        // Terminate the string at the last slash
        *last_slash = '\0'; 
    } else {
        // No slash found, assume the current directory
        strcpy(dir_path, ".");
    }

    if (stat(dir_path, &data) == -1) {
        printf("%s", MSG_ERROR_WRITE);
        return false;
    } 
    else if (!(data.st_mode & S_IWGRP)) {
        printf("%s", MSG_ERROR_WRITE);
        return false;
    } else {
        return true;
    }
}

// XOR the contents of the given file with a set key, and write the result to
// a new file.
void xor_file_contents(char *src_filename, char *dest_filename) {
    FILE *input = fopen(src_filename, "r");
    FILE *output = fopen(dest_filename, "w");

    int c;
    while ((c = fgetc(input)) != EOF) {
        fputc((c ^ XOR_BYTE_VALUE), output);
    }

    fclose(input);
    fclose(output);
}

/////////////////////////////////// SUBSET 2 ///////////////////////////////////

// Search the current directory and its subdirectories for filenames containing
// the search string.
void search_by_filename(char *search_string) {
    if (strcmp(search_string, "") == 0) {
        printf("%s", MSG_ERROR_SEARCH);
    }
    else if (strcmp(search_string, "..") == 0 || strcmp(search_string, ".") == 0 ) {
        printf("%s", MSG_ERROR_RESERVED);
        return;
    }
    
    // create an array of strings of name of the contents of the directory
    int count = 0;
    char *items[MAX_LISTINGS];
    search_dir_by_name(items, ".", &count, search_string);

    if (count == 1) {
        printf("Found in %d filename.\n", count);
    } else {
        printf("Found in %d filenames.\n", count);
    }

    sort_strings(items, count);
    print_dir_items(items, count);
    free_dir_items(items, count);
}

// recurisvely searches through the directory and sub-directories for 
// matches to search string
void search_dir_by_name(char *items[], char *directory, int *count, 
                        char *search_string) {
    // prevent reading over the max_listing limit
    if (*count >= MAX_LISTINGS - 1) {
        return;
    }
    
    DIR *curr_dir = opendir(directory);

    struct dirent *item;
    // for each item in the directory, check if matches the search string
    while ((item = readdir(curr_dir)) != NULL) {
        struct stat data;

        char new_path[MAX_PATH_LEN];
        strcpy(new_path, directory);
        strcat(new_path, "/");
        strcat(new_path, item->d_name);
        stat(new_path, &data);

        // dont bother to check current and parent directory
        if (strcmp(item->d_name, "..") == 0 || strcmp(item->d_name, ".") == 0 ) {
            continue;
        }

        // if directory, check entire relative path for search string, 
        // if file, only check the file name
        char *match;
        if (S_ISDIR(data.st_mode)) {
            match = strstr(new_path, search_string);
        } else {
            match = strstr(item->d_name, search_string);
        }
        
        if (match) {
            items[*count] = strdup(new_path);
            (*count)++;

        }

        // if a directory, recursively iterate through to check for folders
        if (S_ISDIR(data.st_mode)) {
            search_dir_by_name(items, new_path, count, search_string);
        }

    }
    closedir(curr_dir);
}

// Search the current directory and its subdirectories for files containing the
// provided search bytes.
void search_by_content(char *search_bytes, int size) {
    int count = 0;
    content_result **items = malloc(MAX_LISTINGS * sizeof(content_result *));

    search_dir_by_content(items, ".", &count, search_bytes, size);

    if (count == 1) {
        printf("Found in %d file.\n", count);
    } else {
        printf("Found in %d files.\n", count);
    }

    sort_content_results(items, count);
    for (int i = 0; i < count; i++) {
        printf("%d: %s\n", items[i]->matches, items[i]->filename);    
        free(items[i]->filename);
        free(items[i]);
    }
    free(items);
}

// recurisvely searches through the directory and sub-directories for 
// matches to search string
void search_dir_by_content(content_result *items[], char *directory, int *count, 
                           char *search_bytes, int size) {
    // prevent reading over the max_listing limit
    if (*count >= MAX_LISTINGS - 1) {
        return;
    }
    
    DIR *curr_dir = opendir(directory);

    struct dirent *item;
    // for each item in the directory, check if it contains the search string
    while ((item = readdir(curr_dir)) != NULL) {
        struct stat data;

        char new_path[MAX_PATH_LEN];
        strcpy(new_path, directory);
        strcat(new_path, "/");
        strcat(new_path, item->d_name);
        stat(new_path, &data);

        // dont bother to check current and parent directory
        if (strcmp(item->d_name, "..") == 0 || strcmp(item->d_name, ".") == 0 ) {
            continue;
        }

        int matches;
        // if a directory, recursively iterate through to check for folders
        // if file, only check the bytes 
        if (S_ISDIR(data.st_mode)) {
            search_dir_by_content(items, new_path, count, search_bytes, size);
        } 
        else if ((matches = count_matches(new_path, search_bytes, size))){
            items[*count] = malloc(sizeof(content_result));
            items[*count]->filename = strdup(new_path);
            items[*count]->matches = matches;
            (*count)++;
        }
    }
    closedir(curr_dir);
}

// counts the occurances of the search byte and returns the count
int count_matches(char *pathname, char *search_bytes, int size) {
    int matches = 0;
    
    FILE *input = fopen(pathname, "r");
    if (input == NULL) {
        return 0;
    }

    int c;
    char toCheck[MAX_SEARCH_SIZE];
    toCheck[size] = '\0';
    // load in the first bytes to check
    for (int i = 1; i < size; i++) {
        if ((c = fgetc(input)) == EOF) {
            return 0;
        }
        toCheck[i] = c;
    }
    
    // checks the selection of bytes if it matches the search byte
    while ((c = fgetc(input)) != EOF) {
        for (int i = 0; i < size - 1; i++) {
            toCheck[i] = toCheck[i + 1];
        }
        toCheck[size - 1] = c;

        // compares if strings are equal
        int isEqual = true;
        for (int i = 0; i < size; i++) {
            if (toCheck[i] != search_bytes[i]) {
                isEqual = false;
            }
        }
        if (isEqual) {
            matches++;
        }
    }

    fclose(input);
    return matches;
}

/////////////////////////////////// SUBSET 3 ///////////////////////////////////

// encripts a file by rotating each byte by a character in password, in order
void ecb_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    ecb_write(filename, password, ENCIPHER);
}

void ecb_write(char *filename, char password[CIPHER_BLOCK_SIZE], bool shift) {
    // open file to read
    FILE *input = fopen(filename, "r");
    
    struct stat data;
    stat(filename, &data);
    int size = data.st_size;

    // open file to write
    char output_path[MAX_PATH_LEN];
    if (shift == ENCIPHER) {
        snprintf(output_path, sizeof(output_path), "%s.ecb", filename);
    } else {
        snprintf(output_path, sizeof(output_path), "%s.dec", filename);
    }
    
    FILE *output = fopen(output_path, "w");

    
    // for each 16 byte block
    for (int i = 0; i < size; i += CIPHER_BLOCK_SIZE) {
        char *block = read_block(input);

        // apply the shift
        char *shifted;
        if (shift == ENCIPHER) {
            shifted = shift_encrypt(block, password);
        } else {
            shifted = shift_decrypt(block, password);
        }
        
        fwrite(shifted, sizeof(char), CIPHER_BLOCK_SIZE, output);
        free(shifted);
        free(block);

    }

    fclose(input);
    fclose(output);
}

// read in 16 characters and pad the last set of 16 if needed
char *read_block(FILE *input) {
    int len;
    char *block = malloc(CIPHER_BLOCK_SIZE);
    if ((len = fread(block, sizeof(char), CIPHER_BLOCK_SIZE, input)) != 
        CIPHER_BLOCK_SIZE
    ) {
        for (int j = len; j < CIPHER_BLOCK_SIZE; j++) {
            block[j] = '\x00';
        }
    }
    return block;
}

char *shift_encrypt(char *plaintext, char password[CIPHER_BLOCK_SIZE]) {
    char *shifted = malloc(CIPHER_BLOCK_SIZE);
    for (int j = 0; j < CIPHER_BLOCK_SIZE; j++) {
        shifted[j] = bit_rotate(password[j], plaintext[j], ENCIPHER);
    }
    return shifted;
}

char *shift_decrypt(char *ciphertext, char password[CIPHER_BLOCK_SIZE]) {
    char *shifted = malloc(CIPHER_BLOCK_SIZE);
    for (int j = 0; j < CIPHER_BLOCK_SIZE; j++) {
        shifted[j] = bit_rotate(password[j], ciphertext[j], DECIPHER);
    }
    return shifted;
}

// return the value bits rotated n_rotations in the given direction
uint8_t bit_rotate(int n_rotations, uint8_t bits, bool shift) {
    // find the effective number of rotations via modulus
    int rotate = (n_rotations % BYTE + BYTE) % BYTE;
    uint8_t start;
    uint8_t end;
    if (shift == ENCIPHER) {
        start = bits << rotate;
        end = bits >> (BYTE - rotate);
    } else {
        start = bits >> rotate;
        end = bits << (BYTE - rotate);
    }
    return start | end;
}

// decripts a file by rotating each byte by a character in password, in order
void ecb_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    ecb_write(filename, password, DECIPHER);
}

/////////////////////////////////// SUBSET 4 ///////////////////////////////////

void cbc_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    char *initialise = generate_random_string(SEED);

    // open file to read
    FILE *input = fopen(filename, "r");
    
    struct stat data;
    stat(filename, &data);
    int size = data.st_size;

    // open file to write
    char output_path[MAX_PATH_LEN];
    snprintf(output_path, sizeof(output_path), "%s.cbc", filename);
    
    FILE *output = fopen(output_path, "w");

    // for each 16 byte block
    for (int i = 0; i < size; i += CIPHER_BLOCK_SIZE) {
        char *block = read_block(input);

        for (int j = 0; j < CIPHER_BLOCK_SIZE; j++) {
            initialise[j] = block[j] ^ initialise[j];
        }

        // apply the shift
        char *shifted;
        shifted = shift_encrypt(initialise, password);
        
        fwrite(shifted, sizeof(char), CIPHER_BLOCK_SIZE, output);

        free(initialise);
        free(block);
        initialise = shifted;

    }
    free(initialise);
    fclose(input);
    fclose(output);
}

void cbc_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    char *initialise = generate_random_string(SEED);

    // open file to read
    FILE *input = fopen(filename, "r");
    
    struct stat data;
    stat(filename, &data);
    int size = data.st_size;

    // open file to write
    char output_path[MAX_PATH_LEN];
    snprintf(output_path, sizeof(output_path), "%s.dec", filename);
    
    FILE *output = fopen(output_path, "w");

    // for each 16 byte block
    for (int i = 0; i < size; i += CIPHER_BLOCK_SIZE) {
        char *block = read_block(input);

        // apply the shift
        char *shifted;
        shifted = shift_decrypt(block, password);

        for (int j = 0; j < CIPHER_BLOCK_SIZE; j++) {
            shifted[j] = shifted[j] ^ initialise[j];
        }
        
        fwrite(shifted, sizeof(char), CIPHER_BLOCK_SIZE, output);

        free(shifted);
        // copy cipher text to be next initialise string
        for (int j = 0; j < CIPHER_BLOCK_SIZE; j++) {
            initialise[j] = block[j];
        }
        free(block);
    }
    free(initialise);
    fclose(input);
    fclose(output);
}

/////////////////////////////////// PROVIDED ///////////////////////////////////
// Some useful provided functions. Do NOT modify.

// Sort an array of strings in alphabetical order.
// strings:  the array of strings to sort
// count:    the number of strings in the array
// This function is to be provided to students.
void sort_strings(char *strings[], int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            if (strcmp(strings[i], strings[j]) < 0) {
                char *temp = strings[i];
                strings[i] = strings[j];
                strings[j] = temp;
            }
        }
    }
}

// Sort an array of content_result_t in descending order of matches.
// results:  the array of pointers to content_result_t to sort
// count:    the number of pointers to content_result_t in the array
// This function is to be provided to students.
void sort_content_results(content_result *results[], int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            if (results[i]->matches > results[j]->matches) {
                content_result *temp = results[i];
                results[i] = results[j];
                results[j] = temp;
            } else if (results[i]->matches == results[j]->matches) {
                // If the matches are equal, sort alphabetically.
                if (strcmp(results[i]->filename, results[j]->filename) < 0) {
                    content_result *temp = results[i];
                    results[i] = results[j];
                    results[j] = temp;
                }
            }
        }
    }
}

// Generate a random string of length RAND_STR_LEN.
// Requires a seed for the random number generator.
// The same seed will always generate the same string.
// The string contains only lowercase + uppercase letters,
// and digits 0 through 9.
// The string is returned in heap-allocated memory,
// and must be freed by the caller.
char *generate_random_string(int seed) {
    if (seed != 0) {
        srand(seed);
    }
    char *alpha_num_str =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    char *random_str = malloc(RAND_STR_LEN);

    for (int i = 0; i < RAND_STR_LEN; i++) {
        random_str[i] = alpha_num_str[rand() % (strlen(alpha_num_str) - 1)];
    }

    return random_str;
}

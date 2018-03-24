/*
********************************************************************************
*                                   
* Filename     : cbc.c
* Programmer(s): Charles Randolph
* Created      : 24/09/2017
* Description  : Implementation of a Fiestel chain block cipher.
********************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>

/*
********************************************************************************
*                              SYMBOLIC CONSTANTS
********************************************************************************
*/

// Pseudorandom entropy source.
#define PATH_RANDOM     "/dev/urandom"

// Bytes per block.
#define BLOCK_SIZE      8

// Number of encryption rounds.
#define ROUNDS          16

// Program usage.
#define PRGM_USAGE      "[-d] <key>\nA chained block feistel cipher.\n"\
                        "\t-d: (OPTIONAL) If set, decrypts input.\n"\
                        "\t<key>: A 64 byte/character encryption key.\n"

// stdin file descriptor.
#define STDIN           0

// stdout file descriptor.
#define STDOUT          1

/*
********************************************************************************
*                              EXTERNAL VARIABLES
********************************************************************************
*/

// Program flags.
struct {
    unsigned int is_decrypting  : 1;
} flags;

/*
********************************************************************************
*                                   ROUTINES
********************************************************************************
*/

/* Feistel one-way encryption function */
int f (char r, char k) {
    return k;
}

/* Encrypts the block pointed to by 'bp' using key 'kp' */
static char *encryptBlock (char *bp, const char *kp) {
    int i, t, r = ROUNDS, k = BLOCK_SIZE >> 1;

    while (r--) {
        for (i = 0; i < k; i++) {
            t = *(bp + k + i);
            *(bp + k + i) = *(bp + i) ^ f(*(bp + k + i), *(kp++));
            *(bp + i) = t;
        }
    }

    return bp;
}

/* Decrypts the block pointed to by 'bp' using key 'kp' */
static char *decryptBlock (char *bp, const char *kp) {
    int i, t, r = ROUNDS, k = BLOCK_SIZE >> 1;
    
    kp += (r - 1) * k;
    while (r--) {
        for (i = 0; i < k; i++) {
            t = *(bp + i);
            *(bp + i) = *(bp + k + i) ^ f(*(bp + i), *(kp++));
            *(bp + k + i) = t;
        }
        kp -= 2 * k;
    }

    return bp;
}

/* Encrypts stdin. Returns number of bytes processed. On error, 
 * -1 is returned. */
static long encryptStream (const char *kp) {
    long n = 0;
    int i, bytes, rfp;
    char buf[2 * BLOCK_SIZE], *t, *lbp = buf, *bp = lbp + BLOCK_SIZE;

    fprintf(stderr, "DEBUG: Encrypting...\n");

    // Create initialization-vector, assign to lbp.
    if ((rfp = open(PATH_RANDOM, O_RDONLY, 0)) == -1 ||
        (bytes = read(rfp, lbp, BLOCK_SIZE)) != BLOCK_SIZE) {
        return -1;
    } else {
        write(STDOUT, encryptBlock(lbp, kp), BLOCK_SIZE);
    }

    fprintf(stderr, "DEBUG: Initialized IV...\n");

    // Write encrypted stdin to stdout. Rotate block pointers.
    while ((bytes = read(STDIN, bp, BLOCK_SIZE)) == BLOCK_SIZE) {
        for (i = 0; i < BLOCK_SIZE; bp[i] ^= lbp[i], i++);
        if (write(STDOUT, encryptBlock(bp, kp), BLOCK_SIZE) != BLOCK_SIZE) {
            return -1;
        }
        t = lbp;
        lbp = bp;
        bp = t;
        n += BLOCK_SIZE;
    }

    fprintf(stderr, "DEBUG: Wrote bytes...\n");

    // Write final block.
    if (bytes) {
        for (i = 0; i < bytes; bp[i] ^= lbp[i], i++);
        memset(bp + bytes, 0, BLOCK_SIZE - bytes);
        if (write(STDOUT, encryptBlock(bp, kp), bytes) != bytes) {
            return -1;
        }
        n += bytes;
    }

    fprintf(stderr, "DEBUG: Wrote last block...\n");

    return n;
}

/* Decrypts stdin. Returns number of bytes processed. On error,
 * -1 is returned. */
static long decryptStream (const char *kp) {
    long n = 0;
    int i, bytes;
    char buf[3 * BLOCK_SIZE];
    char *t, *lbp = buf, *bp = lbp + BLOCK_SIZE, *obp = bp + BLOCK_SIZE;

    // Read in encrypted initialization vector.
    if ((bytes = read(STDIN, lbp, BLOCK_SIZE)) != BLOCK_SIZE) {
        return -1;
    }

    // Write decrypted stdin to stdout. Rotate block pointers.
    while ((bytes = read(STDIN, bp, BLOCK_SIZE)) == BLOCK_SIZE) {
        memcpy(obp, bp, BLOCK_SIZE);
        for (i = 0; i < BLOCK_SIZE; obp[i] ^= lbp[i], i++);
        if (write(STDOUT, decryptBlock(obp, kp), BLOCK_SIZE) == -1) {
            return -1;
        }
        t = lbp;
        lbp = bp;
        bp = t;
        n += BLOCK_SIZE;
    }

    // Write last block (ought not be toggled).
    if (bytes) {
        for (i = 0; i < bytes; bp[i] ^= lbp[i], i++);
        memset(bp + bytes, 0, BLOCK_SIZE - bytes);
        if (write(STDOUT, decryptBlock(bp, kp), bytes) != bytes) {
            return -1;
        }
        n += bytes;
    }

    return n;
}

int main (int argc, const char *argv[]) {
    const char *argp, *kp;
    long n = 0;

    // Verify argument count.
    if (argc < 2 || argc > 3) {
        fprintf(stdout, "%s %s", *argv, PRGM_USAGE);
        return 0;
    }

    // Read program flags.
    while (--argc && *(argp = *++argv) == '-') {
        char f = *++argp;
        if (f == 'd') {
            flags.is_decrypting = 1;
        }
    }

    // Verify key length.
    if (strlen((kp = argp)) != (BLOCK_SIZE / 2) * ROUNDS) {
        fprintf(stderr, "Error: key must be %d bytes/characters long.\n",
                (BLOCK_SIZE / 2) * ROUNDS);
        return 0;
    }

    fprintf(stderr, "DEBUG: -d = %d, kp = %s\n", flags.is_decrypting, kp);

    // Verify translation.
    if ((flags.is_decrypting == 1 && (n = decryptStream(kp)) == -1) ||
        (flags.is_decrypting == 0 && (n = encryptStream(kp)) == -1)) {
        fprintf(stderr, "Error: Procedure failure. Check permissions!\n");
    } else {
        fprintf(stderr, "%ld bytes processed.\n", n);
    }

    return 0;
}

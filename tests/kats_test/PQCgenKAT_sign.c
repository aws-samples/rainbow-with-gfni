//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include "api.h"
#include "rng.h"
#include "utils_hash.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MARKER_LEN 50

#define KAT_SUCCESS         0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int       FindMarker(FILE *infile, const char *marker);
int       ReadHex(FILE *infile, uint8_t *A, int Length, const char *str);
void      fprintBstr(FILE *fp, const char *S, uint8_t *A, unsigned long long L);
long long jmas_cpucycles(void);
long long jmas_mean(long long *to_check, int len);
int       jmas_cmp_ll(const void *a, const void *b);
long long jmas_median(long long *l, size_t llen);
long long jmas_average(long long *t, size_t tlen);
void jmas_parse_results(long long *c, long long *t, long long *t1, size_t tlen);
void jmas_print_results(
    const char *s, long long *c, long long *t, long long *t1, size_t tlen);

char AlgName[] = "My Alg Name";

_INLINE_ int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t sk_seed[SKSEED_BYTE_LEN] = {0};
    randombytes(sk_seed, SKSEED_BYTE_LEN);

    rainbow_keypair((pk_t *)pk, (sk_t *)sk, sk_seed);
    return 0;
}

_INLINE_ int crypto_sign(uint8_t *      sm,
                         uint64_t *     smlen,
                         const uint8_t *m,
                         uint64_t       mlen,
                         const uint8_t *sk)
{
    uint8_t digest[HASH_BYTE_LEN];
    hash_msg(digest, HASH_BYTE_LEN, m, mlen);

    memcpy(sm, m, mlen);
    *smlen = mlen + SIG_BYTE_LEN;

    return rainbow_sign(sm + mlen, (const sk_t *)sk, digest);
}

_INLINE_ int crypto_sign_open(uint8_t *      m,
                              uint64_t *     mlen,
                              const uint8_t *sm,
                              uint64_t       smlen,
                              const uint8_t *pk)
{
    if(SIG_BYTE_LEN > smlen) {
        return -1;
    }
    memcpy(m, sm, smlen - SIG_BYTE_LEN);
    mlen[0] = smlen - SIG_BYTE_LEN;

    uint8_t digest[HASH_BYTE_LEN];
    hash_msg(digest, HASH_BYTE_LEN, m, *mlen);

    return rainbow_verify(digest, sm + mlen[0], (const pk_t *)pk);
}

int main(int argc, char *argv[])
{
    char     fn_req[32], fn_rsp[32];
    FILE *   fp_req, *fp_rsp;
    uint8_t  seed[48];
    uint8_t  msg[3300];
    uint8_t  entropy_input[48];
    uint8_t *m, *sm, *m1;
    uint64_t mlen, smlen, mlen1;
    int      count;
    int      done;
    uint8_t  pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int      ret_val;
    int      j;
    int      num_tests = 15;

    j = 0;

    if(argc > 1) {
        num_tests = atoi(argv[1]);
        if(num_tests == 0) {
            printf("%ld,%ld,%d\n", CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES,
                   CRYPTO_BYTES);
            exit(0);
        }
    }

    long long c_keypair[num_tests], c_sign[num_tests], c_open[num_tests];
    long long t_keypair[num_tests], t_sign[num_tests], t_open[num_tests];
    long long c_keypair1[num_tests], c_sign1[num_tests], c_open1[num_tests];

    // Create the REQUEST file
    sprintf(fn_req, "PQCsignKAT_%ld.req", CRYPTO_SECRETKEYBYTES);
    if((fp_req = fopen(fn_req, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCsignKAT_%ld.rsp", CRYPTO_SECRETKEYBYTES);
    if((fp_rsp = fopen(fn_rsp, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for(int i = 0; i < 48; i++) entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for(int i = 0; i < num_tests; i++) {
        c_keypair[i] = 0;
        c_sign[i]    = 0;
        c_open[i]    = 0;
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = 33 * (i + 1);
        fprintf(fp_req, "mlen = %ld\n", mlen);
        randombytes(msg, mlen);
        fprintBstr(fp_req, "msg = ", msg, mlen);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "smlen =\n");
        fprintf(fp_req, "sm =\n\n");
    }
    fclose(fp_req);

    // Create the RESPONSE file based on what's in the REQEST file
    if((fp_req = fopen(fn_req, "r")) == NULL) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", AlgName);
    done = 0;
    j    = 0;
    do {
        if(argc <= 2) printf("j=%d\n", j);
        if(FindMarker(fp_req, "count = "))
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if(!ReadHex(fp_req, seed, 48, "seed = ")) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);

        randombytes_init(seed, NULL, 256);

        if(FindMarker(fp_req, "mlen = "))
            fscanf(fp_req, "%ld", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %ld\n", mlen);

        m  = (uint8_t *)calloc(mlen, sizeof(uint8_t));
        m1 = (uint8_t *)calloc(mlen, sizeof(uint8_t));
        sm = (uint8_t *)calloc(mlen + CRYPTO_BYTES, sizeof(uint8_t));

        if(!ReadHex(fp_req, m, (int)mlen, "msg = ")) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);

        // Generate the public/private keypair
        c_keypair[j] = jmas_cpucycles();
        if((ret_val = crypto_sign_keypair(pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        c_keypair1[j] = jmas_cpucycles();
        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

        c_sign[j] = jmas_cpucycles();
        if((ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        c_sign1[j] = jmas_cpucycles();
        fprintf(fp_rsp, "smlen = %ld\n", smlen);
        fprintBstr(fp_rsp, "sm = ", sm, smlen);
        fprintf(fp_rsp, "\n");

        c_open[j] = jmas_cpucycles();
        if((ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        c_open1[j] = jmas_cpucycles();

        if(mlen != mlen1) {
            printf("crypto_sign_open returned bad 'mlen': Got <%ld>, expected "
                   "<%ld>\n",
                   mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }

        if(memcmp(m, m1, mlen)) {
            printf("crypto_sign_open returned bad 'm' value\n");
            return KAT_CRYPTO_FAILURE;
        }

        free(m);
        free(m1);
        free(sm);
        j++;
    } while(!done);

    jmas_parse_results(t_keypair, c_keypair, c_keypair1, num_tests);
    jmas_parse_results(t_sign, c_sign, c_sign1, num_tests);
    jmas_parse_results(t_open, c_open, c_open1, num_tests);

    printf("Times,%llu,%llu,%llu,%llu,%llu,%llu,%ld,%ld,%d,%d\n",
           jmas_median(t_keypair, num_tests), jmas_average(t_keypair, num_tests),
           jmas_median(t_sign, num_tests), jmas_average(t_sign, num_tests),
           jmas_median(t_open, num_tests), jmas_average(t_open, num_tests),
           CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_BYTES, num_tests);

    if(argc < 2) {
        jmas_print_results("crypto_sign_keypair", t_keypair, c_keypair,
                           c_keypair1, num_tests);
        jmas_print_results("crypto_sign", t_sign, c_sign, c_sign1, num_tests);
        jmas_print_results("crypto_sign_open", t_open, c_open, c_open1,
                           num_tests);
    }
    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int FindMarker(FILE *infile, const char *marker)
{
    char line[MAX_MARKER_LEN] = {0};
    int  i, len;

    len = (int)strlen(marker);
    if(len > MAX_MARKER_LEN - 1) len = MAX_MARKER_LEN - 1;

    for(i = 0; i < len; i++) line[i] = fgetc(infile);
    if(line[i] == (char)EOF) return 0;
    line[len] = '\0';

    while(1) {
        if(!strncmp(line, marker, len)) return 1;

        for(i = 0; i < len - 1; i++) line[i] = line[i + 1];
        if((line[len - 1] = fgetc(infile)) == (char)EOF) return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int ReadHex(FILE *infile, uint8_t *A, int Length, const char *str)
{
    int     i, ch, started;
    uint8_t ich;

    if(Length == 0) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if(FindMarker(infile, str))
        while((ch = fgetc(infile)) != EOF) {
            if(!isxdigit(ch)) {
                if(!started) {
                    if(ch == '\n')
                        break;
                    else
                        continue;
                } else
                    break;
            }
            started = 1;
            if((ch >= '0') && (ch <= '9'))
                ich = ch - '0';
            else if((ch >= 'A') && (ch <= 'F'))
                ich = ch - 'A' + 10;
            else if((ch >= 'a') && (ch <= 'f'))
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

            for(i = 0; i < Length - 1; i++) A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void fprintBstr(FILE *fp, const char *S, uint8_t *A, unsigned long long L)
{
    unsigned long long i;

    fprintf(fp, "%s", S);

    for(i = 0; i < L; i++) fprintf(fp, "%02X", A[i]);

    if(L == 0) fprintf(fp, "00");

    fprintf(fp, "\n");
}

long long jmas_cpucycles(void)
{
    unsigned long long result;
    __asm__ volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
                     : "=a"(result)::"%rdx");
    return result;
}
long long jmas_mean(long long to_check[], int len)
{
    long long ret = 0;
    int       i;
    for(i = 0; i < len; i++) {
        //      printf("i=%d\n",i);
        ret += to_check[i];
    }
    ret = ret / len;
    return ret;
}
int jmas_cmp_ll(const void *a, const void *b)
{
    if(*(const long long *)a < *(const long long *)b) return -1;
    if(*(const long long *)a > *(const long long *)b) return 1;
    return 0;
}
long long jmas_median(long long *l, size_t llen)
{
    qsort(l, llen, sizeof(long long), jmas_cmp_ll);

    if(llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

long long jmas_average(long long *t, size_t tlen)
{
    long long acc = 0;
    size_t    i;
    for(i = 0; i < tlen; i++) acc += t[i];
    return acc / (tlen);
}
void jmas_parse_results(long long *c, long long *t, long long *t1, size_t tlen)
{
    size_t i;
    for(i = 0; i < tlen; i++) {
        c[i] = t1[i] - t[i];
    }
}
void jmas_print_results(
    const char *s, long long *c, long long *t, long long *t1, size_t tlen)
{
    size_t i;
    printf("%s", s);
    for(i = 0; i < tlen; i++) {
        c[i] = t1[i] - t[i];
        /*printf("%llu ", t[i]);*/
    }
    printf("\n");
    printf("median:  %llu\n", jmas_median(c, tlen));
    printf("average: %llu\n", jmas_average(c, tlen));
    printf("\n");
}

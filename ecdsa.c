/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <gmp.h>
#include "ecdsa.h"
#include "sha2.h"

static mpz_t p, n;
static ecdsa_p256_t G;

/* ============================= *
 *          mpz_t 연산            *
 * ============================= */

static void mpz_addm(mpz_t rop, const mpz_t a, const mpz_t b, const mpz_t m)
{
    mpz_add(rop, a, b);
    mpz_mod(rop, rop, m);
}

static void mpz_subm(mpz_t rop, const mpz_t a, const mpz_t b, const mpz_t m)
{
    mpz_sub(rop, a, b);
    mpz_mod(rop, rop, m);
}

static void mpz_subm_ui(mpz_t rop, const mpz_t a, const unsigned long int b, const mpz_t m)
{
    mpz_sub_ui(rop, a, b);
    mpz_mod(rop, rop, m);
}

static void mpz_mulm(mpz_t rop, const mpz_t a, const mpz_t b, const mpz_t m)
{
    mpz_mul(rop, a, b);
    mpz_mod(rop, rop, m);
}

static void mpz_mulm_ui(mpz_t rop, const mpz_t a, const unsigned long int b, const mpz_t m)
{
    mpz_mul_ui(rop, a, b);
    mpz_mod(rop, rop, m);
}

/*
 * P-256의 고정된 32바이트 빅 엔디안 배열을 GMP 정수로 내보낸다.
 */
static void mpz_from_bytes(mpz_t z, const void *bytes)
{
    mpz_import(z, ECDSA_P256/8, 1, 1, 0, 0, bytes);
}

/*
 * GMP 정수를 P-256의 고정된 32바이트 빅 엔디안 배열로 내보낸다.
 */
static void bytes_from_mpz(void *bytes, const mpz_t z)
{
    unsigned char buf[ECDSA_P256/8] = {0};
    size_t count = 0;

    mpz_export(buf, &count, 1, 1, 0, 0, z);
    memset(bytes, 0, ECDSA_P256/8);
    memcpy((unsigned char *)bytes + (ECDSA_P256/8 - count), buf, count);
}

/* ============================= *
 *          point 연산            *
 * ============================= */

/*
 * P-256 상의 점의 x, y 좌표를 mpz_t 타입으로 저장한다.
 */
static void mpz_from_point(mpz_t x, mpz_t y, const ecdsa_p256_t *P)
{
    mpz_from_bytes(x, P->x);
    mpz_from_bytes(y, P->y);
}

/*
 * mpz_t 타입의 x, y 좌표를 P-256 상의 점으로 저장한다.
 */
static void point_from_mpz(ecdsa_p256_t *P, const mpz_t x, const mpz_t y)
{
    bytes_from_mpz(P->x, x);
    bytes_from_mpz(P->y, y);
}

/*
 * 주어진 점 P를 무한대 점(Point at Infinity, O)으로 설정한다.
 */
static void set_point_infinite(ecdsa_p256_t *P)
{
    memset(P, 0, sizeof(ecdsa_p256_t));
}

/*
 * 주어진 점 P가 무한대 점(Point at Infinity, O)인지 확인한다.
 * 무한대 점이면 1, 아니면 0을 반환한다.
 */
static int is_point_infinite(const ecdsa_p256_t *P)
{
    static const ecdsa_p256_t INF = {0};
    return memcmp(P, &INF, sizeof(ecdsa_p256_t)) == 0;
}

/*
 * P-256 타원 곡선 위에서 두 점 P와 Q를 더한 결과를 R에 저장한다.
 */
static void point_add(ecdsa_p256_t *R, const ecdsa_p256_t *P, const ecdsa_p256_t *Q)
{
    // P, Q중 어느 한 점이라도 무한대 점이라면, 상대방을 반환한다.
    if (is_point_infinite(P)) {
        *R = *Q;
        return;
    }
    if (is_point_infinite(Q)) {
        *R = *P;
        return;
    }

    mpz_t Rx, Ry, Px, Py, Qx, Qy, lambda, t1, t2;
    mpz_inits(Rx, Ry, Px, Py, Qx, Qy, lambda, t1, t2, NULL);

    mpz_from_point(Px, Py, P);
    mpz_from_point(Qx, Qy, Q);

    if (mpz_cmp(Px, Qx) == 0) {
        mpz_addm(t1, Py, Qy, p);

        // x좌표가 같고, y좌표의 합이 0이다 -> 무한대 점을 반환한다.
        if (mpz_sgn(t1) == 0) {
            set_point_infinite(R);
            goto cleanup;
        }

        // x좌표가 같고, y좌표의 합이 0이 아니다 -> y좌표가 0이 아닌 같은 점이다.

        // t1 = (3*Px^2 - 3) mod p
        mpz_mulm(t1, Px, Px, p);
        mpz_mulm_ui(t1, t1, 3, p);
        mpz_subm_ui(t1, t1, 3, p);

        // t2 = (2*Py)^(-1) mod p
        mpz_addm(t2, Py, Py, p);
        mpz_invert(t2, t2, p);

        // lambda = (3*Px^2 - 3) * (2*Py)^(-1) mod p
        mpz_mulm(lambda, t1, t2, p);
    }

    // x좌표가 다르다 -> 서로 다른 두 점이다.
    else {
        // t1 = (Qy - Py) mod p
        mpz_subm(t1, Qy, Py, p);

        // t2 = (Qx - Px)^(-1) mod p
        mpz_subm(t2, Qx, Px, p);
        mpz_invert(t2, t2, p);
        
        // lambda = (Qy - Py) * (Qx - Px)^(-1) mod p
        mpz_mulm(lambda, t1, t2, p);
    }

    // Rx = lambda^2 - Px - Qx
    mpz_mulm(Rx, lambda, lambda, p);
    mpz_subm(Rx, Rx, Px, p);
    mpz_subm(Rx, Rx, Qx, p);

    // Ry = lambda * (Px - Rx) - Py
    mpz_subm(Ry, Px, Rx, p);
    mpz_mulm(Ry, lambda, Ry, p);
    mpz_subm(Ry, Ry, Py, p);

    point_from_mpz(R, Rx, Ry);

cleanup:
    mpz_clears(Rx, Ry, Px, Py, Qx, Qy, lambda, t1, t2, NULL);
}

/*
 * P-256 타원 곡선 위에서 double-addition 알고리즘을 사용해 점 P를 k번 더한 결과를 R에 저장한다.
 */
static void point_scalar_mul(ecdsa_p256_t *R, const mpz_t z, const ecdsa_p256_t *P)
{
    mpz_t zz;
    ecdsa_p256_t PP = *P;

    mpz_init_set(zz, z);
    mpz_mod(zz, zz, n);

    set_point_infinite(R);

    while (mpz_cmp_ui(zz, 0) > 0) {
        if (mpz_tstbit(zz, 0)) point_add(R, R, &PP);
        point_add(&PP, &PP, &PP);
        mpz_fdiv_q_2exp(zz, zz, 1);
    }

    mpz_clear(zz);
}

/* ============================= *
 *           SHA2 연산            *
 * ============================= */

 /*
 * SHA-2 함수의 인덱스를 입력으로 받아 그 함수의 출력 바이트를 출력한다.
 */
static size_t sha2_hLen(int sha2_ndx)
{
    switch (sha2_ndx)
    {
    case SHA224:        return SHA224_DIGEST_SIZE;
    case SHA256:        return SHA256_DIGEST_SIZE;
    case SHA384:        return SHA384_DIGEST_SIZE;
    case SHA512:        return SHA512_DIGEST_SIZE;
    case SHA512_224:    return SHA224_DIGEST_SIZE;
    case SHA512_256:    return SHA256_DIGEST_SIZE;
    }
    return 0;
}

/*
 * SHA-2 함수의 인덱스로 종류를 선택해 호출한다.
 */
static void sha2(const unsigned char *msg, unsigned int len, unsigned char *digest, int sha2_ndx)
{
    switch (sha2_ndx)
    {
    case SHA224:        sha224(msg, len, digest);       break;
    case SHA256:        sha256(msg, len, digest);       break;
    case SHA384:        sha384(msg, len, digest);       break;
    case SHA512:        sha512(msg, len, digest);       break;
    case SHA512_224:    sha512_224(msg, len, digest);   break;
    case SHA512_256:    sha512_256(msg, len, digest);   break;
    }
}

/* ============================= *
 *          ecdsa 연산            *
 * ============================= */

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    mpz_t Gx, Gy;
    
    mpz_init_set_str(p,  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_init_set_str(n,  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    mpz_inits(Gx, Gy, NULL);
    mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    point_from_mpz(&G, Gx, Gy);
    mpz_clears(Gx, Gy, NULL);
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
    mpz_clears(p, n, NULL);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
    unsigned char buf[ECDSA_P256/8];
    mpz_t dd;

    mpz_init(dd);
    do {
        arc4random_buf(buf, sizeof(buf));
        mpz_from_bytes(dd, buf);
        mpz_mod(dd, dd, n);
    } while (mpz_cmp_ui(dd, 0) == 0);

    bytes_from_mpz(d, dd);
    point_scalar_mul(Q, dd, &G);

    mpz_clear(dd);
}

/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
    if ((sha2_ndx == SHA224 || sha2_ndx == SHA256) && len >= 0x2000000000000000) return ECDSA_MSG_TOO_LONG;

    unsigned char buf[ECDSA_P256/8];
    unsigned char *digest = NULL;
    ecdsa_p256_t P;
    mpz_t e, dd, k, r, s, tmp;
    mpz_inits(e, dd, k, r, s, tmp, NULL);
    mpz_from_bytes(dd, d);
    mpz_mod(dd, dd, n);

    /*
     * 1. e = H(m). H()는 SHA-2 해시함수이다.
     */
    size_t hLen = sha2_hLen(sha2_ndx);
    digest = malloc(hLen);
    sha2(msg, len, digest, sha2_ndx);
    mpz_import(e, hLen, 1, 1, 0, 0, digest);

    /*
     * 2. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다. bitlen(e) <= bitlen(n)
     */
    size_t eLen = mpz_sizeinbase(e, 2);
    if (eLen > ECDSA_P256) mpz_fdiv_q_2exp(e, e, eLen - ECDSA_P256);

    do {
        /*
        * 3. 비밀값 k를 무작위로 선택한다. (0 < k < n)
        */
        arc4random_buf(buf, sizeof(buf));
        mpz_from_bytes(k, buf);
        mpz_mod(k, k, n);
        if (mpz_cmp_ui(k, 0) == 0) continue;

        /*
         * 4. (x1, y1) = kG.
         */
        point_scalar_mul(&P, k, &G);

        /*
         * 5. r = x1 mod n. 만일 r = 0이면 3번으로 다시 간다.
         */
        mpz_from_bytes(r, P.x);
        mpz_mod(r, r, n);
        if (mpz_cmp_ui(r, 0) == 0) continue;

        /*
         * 6. s = k^{-1} * (e + r*d) mod n. 만일 s = 0이면 3번으로 다시 간다.
         */
        mpz_invert(k, k, n);
        mpz_mulm(tmp, r, dd, n);
        mpz_addm(tmp, e, tmp, n);
        mpz_mulm(s, k, tmp, n);
    } while (mpz_cmp_ui(s, 0) == 0);

    /*
     * 7. (r, s)가 서명 값이다.
     */
    bytes_from_mpz(_r, r);
    bytes_from_mpz(_s, s);
 
    mpz_clears(e, dd, k, r, s, tmp, NULL);
    free(digest);
    return 0;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
    if ((sha2_ndx == SHA224 || sha2_ndx == SHA256) && len >= 0x2000000000000000) return ECDSA_MSG_TOO_LONG;
    
    unsigned char *digest = NULL;
    mpz_t r, s, e, s_inv, u1, u2, x1;
    mpz_inits(r, s, e, s_inv, u1, u2, x1, NULL);
    int ret;

    /*
     * 1. r과 s가 [1, n−1] 사이에 있지 않으면 잘못된 서명이다.
     */
    mpz_from_bytes(r, _r);
    mpz_from_bytes(s, _s);

    // r < 0이거나, r > n이거나, s < 0이거나, s > n이면 잘못된 서명
    if (mpz_cmp_ui(r, 0) <= 0 || mpz_cmp(r, n) >= 0 || mpz_cmp_ui(s, 0) <= 0 || mpz_cmp(s, n) >= 0) {
        ret = ECDSA_SIG_INVALID;
        goto cleanup;
    }

    /*
     * 2. e = H(m). H()는 서명에서 사용한 해시함수와 같다.
     */
    size_t hLen = sha2_hLen(sha2_ndx);
    digest = malloc(hLen);
    sha2(msg, len, digest, sha2_ndx);
    mpz_import(e, hLen, 1, 1, 0, 0, digest);
    
    /*
     * 3. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다. bitlen(e) <= bitlen(n)
     */
    size_t eLen = mpz_sizeinbase(e, 2);
    if (eLen > ECDSA_P256) mpz_fdiv_q_2exp(e, e, eLen - ECDSA_P256);

    /*
     * 4. u1 = e * s^{-1} mod n, u2 = r * s^{−1} mod n.
     */
    mpz_invert(s_inv, s, n);
    mpz_mulm(u1, e, s_inv, n);
    mpz_mulm(u2, r, s_inv, n);

    /*
     * 5. (x1, y1) = u1*G + u2*Q. 만일 (x1, y1) = O 이면 잘못된 서명이다.
     */
    ecdsa_p256_t R, T1, T2;
    point_scalar_mul(&T1, u1, &G);
    point_scalar_mul(&T2, u2, _Q);
    point_add(&R, &T1, &T2);

    if (is_point_infinite(&R)) {
        ret = ECDSA_SIG_INVALID;
        goto cleanup;
    }

    /*
     * 6. r = x1 (mod n)이면 올바른 서명이다.
     */
    mpz_from_bytes(x1, R.x);
    mpz_mod(x1, x1, n);
    ret = (mpz_cmp(r, x1) == 0) ? 0 : ECDSA_SIG_MISMATCH;

cleanup:
    mpz_clears(r, s, e, s_inv, u1, u2, x1, NULL);
    free(digest);
    return ret;
}

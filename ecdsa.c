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
static ecdsa_p256_t *G;

static void mpz_addm(mpz_t rop, const mpz_t a, const mpz_t b, const mpz_t m)
{
    mpz_add(rop, a, b);
    mpz_mod(rop, rop, m);
}

static void mpz_addm_ui(mpz_t rop, const mpz_t a, const unsigned long int b, const mpz_t m)
{
    mpz_add_ui(rop, a, b);
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

/**
 * @brief GMP 정수를 P-256의 고정된 32바이트 빅 엔디안 배열로 내보낸다.
 * @param bytes 결과 32바이트가 저장될 출력 버퍼.
 * @param op 내보낼 GMP 정수.
 */
static void mpz_to_bytes(void *bytes, const mpz_t z) {
    unsigned char buf[ECDSA_P256/8] = {0};
    size_t count = 0;

    mpz_export(buf, &count, 1, 1, 0, 0, z);
    memset(bytes, 0, ECDSA_P256/8);
    memcpy((unsigned char *)bytes + (ECDSA_P256/8 - count), buf, count);
}

/**
 * @brief 주어진 점 P를 무한대 점(Point at Infinity, O)으로 설정한다.
 * @param R 무한대 점으로 설정할 타원 곡선 점 포인터.
 */
static void set_infinite(ecdsa_p256_t *R) {
    *R = (ecdsa_p256_t){0};
}

/**
 * @brief 주어진 점 P가 무한대 점(Point at Infinity, O)인지 확인한다.
 * @param P 검사할 타원 곡선 점.
 * @return 무한대 점이면 1 (True), 아니면 0 (False)을 반환한다.
 */
static int is_infinite(const ecdsa_p256_t *P) {
    const unsigned char *p = (const unsigned char *)P;
    for (size_t i = 0; i < sizeof(ecdsa_p256_t); ++i) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

/**
 * @brief P-256 타원 곡선 위에서 두 점 P와 Q를 더하여 결과를 R에 저장한다.
 *
 * 점 덧셈 규칙은 다음과 같다:
 *  - P 또는 Q가 무한대 점이면, 다른 점을 반환한다.
 *  - P.x == Q.x:
 *      * P.y == Q.y 이면 점 배가(Point Doubling)를 수행한다.
 *      * P.y != Q.y 이면 결과는 무한대 점이다.
 *  - 그 외에는 일반적인 점 덧셈(Point Addition) 공식을 사용한다.
 *
 * @param R 결과가 저장될 점 포인터.
 * @param P 첫 번째 입력 점.
 * @param Q 두 번째 입력 점.
 * @return 항상 0을 반환한다.
 */
static int ecdsa_p256_point_add(ecdsa_p256_t *R, const ecdsa_p256_t *P, const ecdsa_p256_t *Q) {
    // P, Q중 어느 한 점이라도 무한대 점이라면, 상대방을 반환한다.
    if (is_infinite(P)) {
        *R = *Q;
        return 0;
    }
    if (is_infinite(Q)) {
        *R = *P;
        return 0;
    }

    mpz_t Rx, Ry, Px, Py, Qx, Qy;
    mpz_t lambda, t1, t2;

    mpz_inits(Rx, Ry, Px, Py, Qx, Qy, NULL);
    mpz_inits(lambda, t1, t2, NULL);

    mpz_import(Px, ECDSA_P256/8, 1, 1, 0, 0, P->x);
    mpz_import(Py, ECDSA_P256/8, 1, 1, 0, 0, P->y);
    mpz_import(Qx, ECDSA_P256/8, 1, 1, 0, 0, Q->x);
    mpz_import(Qy, ECDSA_P256/8, 1, 1, 0, 0, Q->y);

    if (mpz_cmp(Px, Qx) == 0) {
        // x좌표가 같고, y좌표가 같다 -> 같은 점이다.
        if (mpz_cmp(Py, Qy) == 0) {
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
        // x좌표가 같고, y좌표가 다르다 -> 무한대 점을 반환한다.
        else {
            set_infinite(R);
            mpz_clears(Rx, Ry, Px, Py, Qx, Qy, NULL);
            mpz_clears(lambda, t1, t2, NULL);
            return 0;
        }
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

    mpz_to_bytes(R->x, Rx);
    mpz_to_bytes(R->y, Ry);

    mpz_clears(Rx, Ry, Px, Py, Qx, Qy, NULL);
    mpz_clears(lambda, t1, t2, NULL);
    return 0;
}

/**
 * @brief P-256 타원 곡선 위에서 스칼라 k와 점 P를 곱하여 결과 R = kP를 계산한다.
 * @param R 결과 점 kP가 저장될 점 포인터.
 * @param k GMP mpz_t 타입으로 표현된 스칼라.
 * @param P 곱셈을 수행할 입력 점.
 */
static void ecdsa_p256_scalar_mul(ecdsa_p256_t *R, const mpz_t k, const ecdsa_p256_t *P) {
    ecdsa_p256_t Q = *P;
    mpz_t kk;

    mpz_init_set(kk, k);
    mpz_mod(kk, kk, n);
    set_infinite(R);

    while (mpz_sgn(kk) > 0) {
        if (mpz_tstbit(kk, 0)) ecdsa_p256_point_add(R, R, &Q);
        ecdsa_p256_point_add(&Q, &Q, &Q);
        mpz_fdiv_q_2exp(kk, kk, 1);
    }

    mpz_clear(kk);
}

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    // p 공간 할당 및 초기화
    mpz_init_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);

    // n 공간 할당 및 초기화
    mpz_init_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    
    // G 공간 할당 및 초기화
    G = malloc(sizeof(ecdsa_p256_t));
    mpz_t Gx, Gy;
    mpz_init_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_init_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    mpz_to_bytes(G->x, Gx);
    mpz_to_bytes(G->y, Gy);
    mpz_clear(Gx);
    mpz_clear(Gy);
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
    mpz_clears(p, n);
    free(G);
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
        mpz_import(dd, sizeof(buf), 1, 1, 0, 0, buf);
        mpz_mod(dd, dd, n);
    } while (mpz_cmp_ui(dd, 0) == 0);

    mpz_to_bytes(d, dd);
    ecdsa_p256_scalar_mul(Q, dd, G);
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
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
}

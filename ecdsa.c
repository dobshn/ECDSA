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
    mpz_export(G->x, NULL, 1, 1, 0, 0, Gx);
    mpz_export(G->y, NULL, 1, 1, 0, 0, Gy);
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

/*
 * libsecurity.c - Cryptographic primitives and key management using OpenSSL
 */
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>

#define SECRET_SIZE 32 //Size of the ECDH shared secret in bytes
#define MAC_SIZE 32 //  
#define IV_SIZE 16

EVP_PKEY* ec_priv_key = NULL;
EVP_PKEY* ec_peer_public_key = NULL;
EVP_PKEY* ec_ca_public_key = NULL;
size_t cert_size = 0;
uint8_t* certificate = NULL;
size_t pub_key_size = 0;
uint8_t* public_key = NULL;
uint8_t* secret = NULL;
uint8_t* enc_key = NULL;
uint8_t* mac_key = NULL;




/*
load_private_key:
    Read an EC private key from a DER-encoded file.
    Exit on failure
*/
void load_private_key(const char* filename) {
    FILE* fp = fopen(filename, "r"); //Open key file
    if (fp == NULL) {
        fprintf(stderr, "Error: invalid private key filename\n");
        exit(255);
    }
    ec_priv_key = d2i_PrivateKey_fp(fp, NULL);
    if (ec_priv_key == NULL) {
        fprintf(stderr, "Error: invalid private key\n");
        exit(255);
    }
    fclose(fp);
}


//Getter/setter for the loaded private key
EVP_PKEY* get_private_key() {
    return ec_priv_key;
}

void set_private_key(EVP_PKEY* key) {
    ec_priv_key = key;
}



/**
 * load_public_key:
 * Deserialize a DER-encoded public key from memory
*/
void load_peer_public_key(const uint8_t* peer_key, size_t size) {
    BIO* bio = BIO_new_mem_buf(peer_key, size);
    ec_peer_public_key = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
}


/**
 * load_ca_public_key:
 *   Read CA's public key from a DER-encoded file to verify certs.
 *   Exits on failure.
 */
void load_ca_public_key(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr,
                "Error: invalid certificate authority public key filename\n");
        exit(255);
    }
    ec_ca_public_key = d2i_PUBKEY_fp(fp, NULL);
    if (ec_ca_public_key == NULL) {
        fprintf(stderr, "Error: invalid certificate authority public key\n");
        exit(255);
    }
    fclose(fp);
}


/**
 * load_certificate:
 *   Read a raw TLV-encoded certificate file into memory.
 */
void load_certificate(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: invalid certificate filename\n");
        exit(255);
    }
    fseek(fp, 0, SEEK_END);
    cert_size = ftell(fp);
    certificate = malloc(cert_size);
    fseek(fp, 0, 0);
    fread(certificate, cert_size, 1, fp);
    fclose(fp);
}

/**
 * generate_private_key:
 *   Create a new ephemeral EC key on curve P-256.
 */
void generate_private_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &ec_priv_key);

    EVP_PKEY_CTX_free(pctx);
}


/**
 * derive_public_key:
 *   Extract the public portion of ec_priv_key into DER format.
 */
void derive_public_key() {
    pub_key_size = i2d_PUBKEY(ec_priv_key, &public_key);
}


/**
 * derive_secret:
 *   Perform ECDH between ec_priv_key and ec_peer_public_key.
 */
void derive_secret() {
    size_t sec_size = SECRET_SIZE;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ec_priv_key, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, ec_peer_public_key);
    secret = malloc(sec_size);
    EVP_PKEY_derive(ctx, secret, &sec_size);

    EVP_PKEY_CTX_free(ctx);
}


/**
 * derive_keys:
 *   Run HKDF-SHA256 on the shared secret using provided salt.
 *   Produces two keys: enc_key (info="enc") and mac_key (info="mac").
 */
void derive_keys(const uint8_t* salt, size_t size) {
    EVP_KDF* kdf;
    EVP_KDF_CTX* kctx;
    OSSL_PARAM params[5];

    kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    params[0] =
        OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t) 7);
    params[1] =
        OSSL_PARAM_construct_octet_string("key", secret, (size_t) SECRET_SIZE);
    params[2] = OSSL_PARAM_construct_octet_string("info", "enc", (size_t) 3);
    params[3] = OSSL_PARAM_construct_octet_string("salt", (void*) salt, size);
    params[4] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(kctx, params);

    enc_key = malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, enc_key, SECRET_SIZE, NULL);

    params[2] = OSSL_PARAM_construct_octet_string("info", "mac", (size_t) 3);
    EVP_KDF_CTX_set_params(kctx, params);

    mac_key = malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, mac_key, SECRET_SIZE, NULL);

    EVP_KDF_CTX_free(kctx);
}


/**
 * sign:
 *   Produce an ECDSA-SHA256 signature of 'data', writing into 'signature'.
 *   Returns the signature length.
 */
size_t sign(uint8_t* signature, const uint8_t* data, size_t size) {
    size_t sig_size = 255;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_priv_key);
    EVP_DigestSignUpdate(mdctx, data, size);
    EVP_DigestSignFinal(mdctx, signature, &sig_size);

    EVP_MD_CTX_free(mdctx);
    return sig_size;
}


/**
 * verify:
 *   Verify ECDSA-SHA256 signature using given authority key.
 *   Returns 1 if valid, 0 otherwise.
 */
int verify(const uint8_t* signature, size_t sig_size, const uint8_t* data,
           size_t size, EVP_PKEY* authority) {
    int result;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, authority);
    EVP_DigestVerifyUpdate(mdctx, data, size);
    result = EVP_DigestVerifyFinal(mdctx, signature, sig_size);

    EVP_MD_CTX_free(mdctx);
    return result;
}


/**
 * generate_nonce:
 *   Fill buf with cryptographically secure random bytes.
 */
void generate_nonce(uint8_t* buf, size_t size) { RAND_bytes(buf, size); }


/**
 * encrypt_data:
 *   Encrypt 'data' under AES-256-CBC with PKCS#7 padding.
 *   Outputs IV and ciphertext. Returns ciphertext length.
 */
size_t encrypt_data(uint8_t* iv, uint8_t* cipher, const uint8_t* data, size_t size) {
    int cipher_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    generate_nonce(iv, IV_SIZE);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv);
    EVP_EncryptUpdate(ctx, cipher, &cipher_size, data, size);
    EVP_EncryptFinal_ex(ctx, cipher + cipher_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_size + padding_size;
}


/**
 * decrypt_cipher:
 *   Decrypt AES-256-CBC ciphertext using stored enc_key and provided IV.
 *   Returns plaintext length after removing padding.
 */
size_t decrypt_cipher(uint8_t* data, const uint8_t* cipher, size_t size, const uint8_t* iv) {
    int data_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv);
    EVP_DecryptUpdate(ctx, data, &data_size, cipher, size);
    EVP_DecryptFinal_ex(ctx, data + data_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return data_size + padding_size;
}


/**
 * hmac:
 *   Compute HMAC-SHA256 over data with mac_key. Output is MAC_SIZE bytes.
 */
void hmac(uint8_t* digest, const uint8_t* data, size_t size) {
    unsigned int mac_size = MAC_SIZE;
    HMAC(EVP_sha256(), mac_key, SECRET_SIZE, data, size, digest, &mac_size);
}

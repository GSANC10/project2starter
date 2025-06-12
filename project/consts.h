#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) (void) (x)

// States
#define SERVER 0
#define CLIENT 1

// Security states
//Handshake state identifiers
#define SERVER_CLIENT_HELLO_AWAIT 0
#define CLIENT_CLIENT_HELLO_SEND 1
#define SERVER_SERVER_HELLO_SEND 2
#define CLIENT_SERVER_HELLO_AWAIT 3
#define SERVER_FINISHED_AWAIT 6
#define CLIENT_FINISHED_SEND 7
#define DATA_STATE 8

// Security sizes
//Fixed sizes for security primtives
#define NONCE_SIZE 32
#define SECRET_SIZE 32
#define MAC_SIZE 32
#define IV_SIZE 16

//TLV type identifiers
#define CLIENT_HELLO 0x10
#define NONCE 0x01
#define PUBLIC_KEY 0x02

#define CERTIFICATE 0xA0
#define DNS_NAME 0xA1
#define SIGNATURE 0xA2

#define SERVER_HELLO 0x20
#define HANDSHAKE_SIGNATURE 0x21

#define FINISHED 0x30
#define TRANSCRIPT 0x04

#define DATA 0x50
#define IV 0x51
#define CIPHERTEXT 0x52
#define MAC 0x53

// Helpers
#define MIN(a, b) (a > b ? b : a)
#define MAX(c, d) (c > d ? c : d)


//Debug print functions
static inline void print(char* txt) { fprintf(stderr, "%s\n", txt); }
static inline void print_hex(uint8_t* buf, uint16_t len) {
    for (int i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", *(buf + i));
    }
    fprintf(stderr, "\n");
}

//Maximum number of child TLVs nested inside a parent
#define MAX_CHILDREN 10
//Marker for extended length encoding in TLV
#define VN3 0xFD


/**
 * tlv struct:
 *  type    - 1-byte TLV type identifier
 *  length  - effective length of val (in bytes)
 *  val     - pointer to raw byte array (for leaf TLVs)
 *  children- array of pointers to nested child TLVs
 */
typedef struct tlv {
    uint8_t type;
    uint16_t length;
    uint8_t* val;
    struct tlv* children[MAX_CHILDREN];
} tlv;



/**
 * create_tlv:
 *  Allocate and zero-initialize a TLV struct, setting its type.
 */
static inline tlv* create_tlv(uint8_t type) {
    tlv* t = (tlv*) calloc(1, sizeof(tlv)); //Calloc zeros children and al
    t->type = type; //Record TLV type
    return t;
}

/**
 * add_val:
 *  Attach a raw byte buffer to a leaf TLV, copying 'size' bytes from 'val'.
 *  Updates the TLV's length accordingly.
 */
static inline void add_val(tlv* t, uint8_t* val, uint16_t size) {
    uint8_t* buf = (uint8_t*) malloc(size);
    memcpy(buf, val, size); //deep copy the value bytes
    t->val = buf; //store pointer
    t->length = size; //set payload length
}


/**
 * add_tlv:
 *  Add a child TLV to a parent, updating parent's length to include:
 *   1 byte for child type,
 *   1 or 3 bytes for child length encoding,
 *   child->length bytes for the payload.
 */
static inline void add_tlv(tlv* parent, tlv* child) {
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (parent->children[i] == NULL) {
            parent->children[i] = child;
            //Increase parent length: type + length-of-length + payload
            parent->length += 1;
            parent->length += child->length > (VN3 - 1) ? 3 : 1;
            parent->length += child->length;
            break;
        }
    }
}


/**
 * free_tlv:
 *  Recursively free a TLV tree: first free val, then children, then the TLV itself.
 */
static inline void free_tlv(tlv* t) {
    if (t->val != NULL) {
        free(t->val);
    }

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (t->children[i] != NULL)
            free_tlv(t->children[i]);
    }

    free(t);
}


/**
 * serialize_tlv:
 *  Write a TLV (and nested children) into 'buf'.
 *  Returns total bytes written.
 */
static inline uint16_t serialize_tlv(uint8_t* buf, tlv* t) {
    uint8_t* buffer = buf;
    *buf = t->type; //1 byte type
    buf += 1;
    uint16_t len = t->length;
    if (len <= VN3 - 1) {
        *buf = (uint8_t) len;
        buf += 1; //Short length fits in 1 byte
    } else {
        *buf = VN3; //extended length marker
        buf += 1; // 2-byte length in network order
        *((uint16_t*) buf) = htons(len);
        buf += 2;
    }

    if (t->val != NULL) {
        memcpy(buf, t->val, t->length); //copy raw payload
        buf += t->length;
    } else {
        //Recursively seralize each non-null child
        for (int i = 0; i < MAX_CHILDREN; i++) {
            if (t->children[i] != NULL) {
                uint16_t clen = serialize_tlv(buf, t->children[i]);
                buf += clen;
            }
        }
    }

    return buf - buffer; //Total bytes
}



/**
 * deserialize_tlv:
 *  Parse a TLV from 'buf' up to 'size' bytes.
 *  Recursively builds child TLVs for composite types.
 *  Returns allocated TLV or NULL on parse error.
 */
static inline tlv* deserialize_tlv(uint8_t* buf, uint16_t size) {
    uint8_t* buffer = buf;
    uint8_t type = *buf;
    buf += 1;
    if (buf - buffer >= size)
        return NULL;
    tlv* t = create_tlv(type);
    if (*buf == VN3) {
        buf += 1;
        if (buf - buffer + 1 >= size)
            return NULL;
        t->length = ntohs(*((uint16_t*) buf));
        buf += 2;
    } else {
        t->length = *buf;
        buf++;
    }
    if (buf - buffer + t->length > size)
        return NULL;

    //Composite vs leaf types
    if (type == CLIENT_HELLO || type == SERVER_HELLO || type == CERTIFICATE ||
        type == FINISHED || type == DATA) {
        uint8_t* buf2 = buf;
        for (int i = 0; i < MAX_CHILDREN; i++) {
            if ((buf - buf2) == t->length)
                break;
            tlv* child = deserialize_tlv(buf, t->length - (buf2 - buf));
            if (child == NULL)
                return NULL;
            t->children[i] = child;
            buf += 1;
            if (buf - buf2 >= t->length)
                return NULL;
            if (child->length <= VN3 - 1) {
                buf += 1;
            } else {
                buf += 3;
            }
            if (buf - buf2 >= t->length)
                return NULL;
            buf += child->length;
            if (buf - buf2 > t->length)
                return NULL;
        }
    } else {
        add_val(t, buf, t->length);
    }

    return t;
}


/**
 * get_tlv:
 *  Recursively search a TLV tree for a node matching 'type'.
 *  Returns pointer to found TLV or NULL.
 */
static inline tlv* get_tlv(tlv* t, uint8_t type) {
    if (t->type == type) {
        return t;
    }

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (t->children[i] != NULL && t->children[i]->type == type) {
            return t->children[i];
        }
    }

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (t->children[i] == NULL) continue;
        tlv* child = get_tlv(t->children[i], type);
        if (child != NULL)
            return child;
    }

    return NULL;
}



/**
 * print_tlv_bytes:
 *  Debug utility: iterate over raw TLV bytes in 'buffer' of length 'len',
 *  printing each Type and Length field and hex-dumping leaf values.
 */
static inline void print_tlv_bytes(uint8_t* buffer, uint16_t len) {
    uint8_t* buf = buffer;

    while (buf - buffer < len) {
        uint8_t type = *buf;
        fprintf(stderr, "Type: 0x%02x\n", type);
        buf += 1;
        if (buf - buffer >= len) {
            print("MALFORMED");
            return;
        }

        uint16_t length = 0;
        if (*buf == VN3) {
            buf += 1;
            if (buf - buffer + 1 >= len) {
                print("MALFORMED");
                return;
            }
            length = ntohs(*((uint16_t*) buf));
            buf += 2;
        } else {
            length = *buf;
            buf++;
            if (buf - buffer + length > len) {
                print("MALFORMED");
                return;
            }
        }
        fprintf(stderr, "Length: %hu\n", length);

        if (type == CLIENT_HELLO || type == SERVER_HELLO || type == FINISHED ||
            type == CERTIFICATE || type == DATA)
            continue;
        else {
            uint16_t min_length = MIN(len - (buf - buffer), length);
            print_hex(buf, min_length);
            buf += min_length;
        }
    }
}

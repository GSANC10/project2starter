#include "consts.h"
#include "libsecurity.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

int main(int argc, char** argv) {
    UNUSED(argc);
    load_private_key(argv[1]);
    derive_public_key();
    load_private_key(argv[2]);

    tlv* cert = create_tlv(CERTIFICATE);

    tlv* dn = create_tlv(DNS_NAME);
    add_val(dn, (uint8_t*) argv[3], strlen(argv[3]) + 1);

    tlv* pub_key = create_tlv(PUBLIC_KEY);
    add_val(pub_key, public_key, pub_key_size);

    tlv* s = create_tlv(SIGNATURE);
    uint8_t b[1000];
    uint16_t offset = 0;
    offset += serialize_tlv(b + offset, dn);
    offset += serialize_tlv(b + offset, pub_key);
    uint8_t sig[255];
    size_t sig_size = sign(sig, b, offset);
    add_val(s, sig, sig_size);

    add_tlv(cert, dn);
    add_tlv(cert, pub_key);
    add_tlv(cert, s);

    uint16_t len = serialize_tlv(b, cert);

    FILE* fp = fopen(argv[4], "w");
    fwrite(b, len, 1, fp);
    fclose(fp);

    /* print_tlv_bytes(b, len); */
    /* tlv* cert2 = deserialize_tlv(b, len); */
    /* uint16_t len2 = serialize_tlv(b, cert2); */
    /* print_tlv_bytes(b, len2); */

    return 0;
}

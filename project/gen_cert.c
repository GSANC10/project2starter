#include "consts.h"
#include "libsecurity.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>


//This little utility-let's call it gen_cert-s there to build your TLV-encoded certificate blob (the file server.cert.bin) that your server will present in its Server-Hello. Here's the point of each phrase:
    //1. Key loading & public-key derivation
int main(int argc, char** argv) {
    UNUSED(argc);
    //First load_private_key reads your server's long-term private key into memory
    //Derive_public_key() computes the matching public key bytes (P-256, DER-encoded) and stashes t
    load_private_key(argv[1]);
    derive_public_key();
    //Switch to signing key - now you load teh CA's private key (the same one that signed your server's certificate). This is the key you'll use to create the certificate's signature
    load_private_key(argv[2]);


    //Build the TLV tree for teh certfiicate
    tlv* cert = create_tlv(CERTIFICATE);
    //this is the outer wrapper (type 0xA0) that will contain three child TLVs: the DNS name, the server's public key, and the CA's signature. 

    //DNS-Name TLV
    //Wraps the hostname (e.g. "example.com") you pass as argv[3].
    tlv* dn = create_tlv(DNS_NAME);
    add_val(dn, (uint8_t*) argv[3], strlen(argv[3]) + 1);


    //Embed public key you derived earlier
    tlv* pub_key = create_tlv(PUBLIC_KEY);
    add_val(pub_key, public_key, pub_key_size);

    tlv* s = create_tlv(SIGNATURE);
    uint8_t b[1000];
    uint16_t offset = 0;





    //Here we are computing Sig_CA(DNS-Name || PubKey) and packaging it as a TLB (type 0xA2)
    // 1) Serialize DNS and pub_key TLVs into buffer 'b[]'.
    offset += serialize_tlv(b + offset, dn);
    offset += serialize_tlv(b + offset, pub_key);
    uint8_t sig[255];
    // 2) Sign that concatentation with the CA's private key.
    size_t sig_size = sign(sig, b, offset);
    // 3) Wrap the raw signature bytes in a signature TLV
    add_val(s, sig, sig_size);

    add_tlv(cert, dn);
    add_tlv(cert, pub_key);
    add_tlv(cert, s);


    //Nest the three children under the CERTIFICATE parent, then flatten the whole tree into the byte array b[]
    uint16_t len = serialize_tlv(b, cert);


    //Dumps those len bytes into the ouput file you specify (e.g. server_cert.bin)
    FILE* fp = fopen(argv[4], "w");
    fwrite(b, len, 1, fp);
    fclose(fp);

    //Ultimately here instead of hand-crafting or copying certificate files, you regenerate the exact TLV format your protocol expects
    /* print_tlv_bytes(b, len); */
    /* tlv* cert2 = deserialize_tlv(b, len); */
    /* uint16_t len2 = serialize_tlv(b, cert2); */
    /* print_tlv_bytes(b, len2); */

    return 0;
}

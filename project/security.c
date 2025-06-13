#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

//Global variables for security state and handshake context
int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL; //Our long-term or ephermal EC private key
tlv* client_hello = NULL; //Stored TLV tree for the ClientHello message
tlv* server_hello = NULL; //Stored TLV tree for the SererHello message

uint8_t ts[1000] = {0}; //Buffer to acumulate the handhsake transcript (salt)
uint16_t ts_len = 0; //Current length of the trasncript in ts[]

bool inc_mac = false;  // For testing only: send incorrect MACs





/*init_src: Initialize the security layer. Sets global state and host name, toggles testing flag, and configures stdin for non-blocking I/O
 * @param initial_state  One of CLIENT_CLIENT_HELLO_SEND, SERVER_CLIENT_HELLO_AWAIT, etc.
 * @param host           Expected hostname for certificate validation (client only)
 * @param bad_mac        If true, libsecurity will send incorrect MACs (for testing)
 * 
*/
void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state; //Save the starting protocol state
    hostname = host; //Store the DNS name to verify in the handshake
    inc_mac = bad_mac; //Enable or disable MAC corruption for testing
    init_io(); //Setup non-blocking stdin/stout via io.h



    //Optionally perform state-specific initialization here:
    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        //Client will send the ClientHello to immediately on first input_sec() call
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        //Server will wait to receive a ClientHello via output_sec()
    }
}



/*
input_sec: Produces the next oubtound security message based on current state. Called by the reliability layer when writable
Note that we are usign Buffer to write serialized TLV message into, max_length to write the maximumm capacity of buf, and return is the number of bytes written (>0), or 0 if nothing to send in this state
*/


//This function allows you to provide input to the transport layer. The transport layer will call this method when creating new packets. As such, it’s guaranteed that any data you write to the buf argument will all be in one packet (just make sure to not write more than max_length, or else you’ll get a buffer overflow).

//WORK TO DO HERE GABE
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
        case CLIENT_CLIENT_HELLO_SEND: {
            //Generate keys per spec
            generate_private_key();
            derive_public_key();
            //Create TLV packet
            tlv* ch = create_tlv(CLIENT_HELLO);
            //Create nonce object
            tlv* nn = create_tlv(NONCE);
            //Generate nonce
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            //Place this data in nonce
            add_val(nn, nonce, NONCE_SIZE);
            //Add nonce tlv as part of client hello
            add_tlv(ch, nn);
            //Key
            tlv* pk = create_tlv(PUBLIC_KEY);
            add_val(pk, public_key, pub_key_size);
            add_tlv(ch, pk);
            //Send to trasnport layer & serialize bytes
            uint16_t len = serialize_tlv(buf, ch);
            fprintf(stderr, "=== CLIENT HELLO OUTGOING ===\n");
            print_tlv_bytes(buf, len);
            fprintf(stderr, "Caching into ts[%u..%u):\n", ts_len, ts_len + (uint16_t)len);
            print_hex(buf, len);
            // Save to transcript
            memcpy(ts + ts_len, buf, len);
            ts_len += len;

            // Clean up
            free_tlv(ch);

            // Advance
            state_sec = CLIENT_SERVER_HELLO_AWAIT;
            return len;
        }
        case SERVER_SERVER_HELLO_SEND: {
            //load server certificate
            load_certificate("server_cert.bin");
            //private key for handshake
            load_private_key("server_key.bin");
            //ECDH keypair. Needed
            generate_private_key();
            derive_public_key();
            //build serverhello man
            tlv* sh = create_tlv(SERVER_HELLO);
            tlv* nonce_tlv = create_tlv(NONCE);
            uint8_t srv_nonce[NONCE_SIZE];
            generate_nonce(srv_nonce, NONCE_SIZE);
            add_val(nonce_tlv, srv_nonce, NONCE_SIZE);
            add_tlv(sh, nonce_tlv);
            //include certificate
            tlv* cert_tree = deserialize_tlv(certificate, cert_size);
            add_tlv(sh, cert_tree);
            //include ephemeral public key
            tlv* epk = create_tlv(PUBLIC_KEY);
            add_val(epk, public_key, pub_key_size);
            add_tlv(sh, epk);
            //serialize without signature
            uint8_t tmp[2048];
            uint16_t partial_len = serialize_tlv(tmp, sh);
            //sign over full transcript
            size_t total = ts_len + partial_len;
            uint8_t* to_sign = malloc(total);
            memcpy(to_sign, ts, ts_len);
            memcpy(to_sign + ts_len, tmp, partial_len);
            uint8_t sig[255]; size_t sig_len = sign(sig, to_sign, total);
            free(to_sign);
            // attach signature
            tlv* hsig = create_tlv(HANDSHAKE_SIGNATURE);
            add_val(hsig, sig, sig_len);
            add_tlv(sh, hsig);
            //serialize full
            size_t out_len = serialize_tlv(buf, sh);
            //append to transcript
            memcpy(ts + ts_len, buf, out_len);
            ts_len += out_len;
            free_tlv(sh);
            //next expect Finished
            state_sec = SERVER_FINISHED_AWAIT;
            return out_len;
        }
        //Correctly HMAC's the entire transcript
        case CLIENT_FINISHED_SEND: {
            //Compute HMAC over the concatenated transcript
            uint8_t mac_val[MAC_SIZE];
            hmac(mac_val, ts, ts_len);
            //Build tlv
            tlv* fin = create_tlv(FINISHED);
            //Allocate a node of type TLV
            tlv* tr = create_tlv(TRANSCRIPT); 
            add_val(tr, mac_val, MAC_SIZE);
            //Build leaf TLV (transcript), carrying the 32-byte HMAC you just computed above
            add_tlv(fin, tr);
            //Nest Transcript TLV inside Finished TLV. Now fin->length reflects the nested TLV's size + headers
            size_t len = serialize_tlv(buf, fin);
            //Move to data state now
            state_sec = DATA_STATE;
            return len;
        }
        case DATA_STATE: {
            // Data state: encrypt application data with libsecurity and wrap in DATA TLV
            uint8_t plaintext[1024]; 
            size_t pt_len = input_io(plaintext, sizeof(plaintext));
            //Quick check, safety
            if(pt_len <= 0){
                return 0;
            }
            //Let's encrypt this shit
            uint8_t iv[IV_SIZE];
            uint8_t ciphertext[2048];
            size_t ct_len = encrypt_data(iv, ciphertext, plaintext, pt_len);
            //Set up MAC
            uint8_t mac_in[IV_SIZE + ct_len];
            memcpy(mac_in, iv, IV_SIZE);
            memcpy(mac_in + IV_SIZE, ciphertext, ct_len);
            uint8_t mac_out[MAC_SIZE];
            hmac(mac_out, mac_in, IV_SIZE + ct_len);
            //Again we going to cook up the DATATLV
            tlv* dt = create_tlv(DATA);
            tlv* ivt = create_tlv(IV); add_val(ivt, iv, IV_SIZE);
            tlv* cpt = create_tlv(CIPHERTEXT); add_val(cpt, ciphertext, ct_len);
            tlv* mct = create_tlv(MAC); add_val(mct, mac_out, MAC_SIZE);
            add_tlv(dt, ivt); add_tlv(dt, cpt); add_tlv(dt, mct);
            return serialize_tlv(buf, dt);
    }
    default:
        //No message to send in other states
        return 0;
    }
}


/*
output_src: 
Process an inbound security message based on current state.
Called by the reliabilty layer when readable.
buf: buffer containing received bytes (one TLV record)
length: Number of bytes in buf
*/
void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        // parse ClientHello, cache ts, extract client pubkey
            tlv* ch = deserialize_tlv(buf, length);
            if (!ch) exit(6);
            memcpy(ts, buf, length); ts_len = length;
            tlv* cpk = get_tlv(ch, PUBLIC_KEY);
            if (!cpk) { free_tlv(ch); exit(6); }
            load_peer_public_key(cpk->val, cpk->length);
            free_tlv(ch);
            state_sec = SERVER_SERVER_HELLO_SEND;
            break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        //PARSE SHIT
        tlv* ch = deserialize_tlv(buf, length);
        if (ch == NULL) {
            // malformed or unexpected
            exit(6);
        }

        //cache clienthello
        memcpy(ts, buf, length);
        ts_len = length;

        //extract ephemeral key fromc lient
        tlv* cpk = get_tlv(ch, PUBLIC_KEY);
        if (cpk == NULL) {
            free_tlv(ch);
            exit(6);
        }
        load_peer_public_key(cpk->val, cpk->length);

        state_sec = CLIENT_FINISHED_SEND;

        free_tlv(ch);
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        // 1) Parse the Finished TLV
        tlv* fin = deserialize_tlv(buf, length);
        tlv* tr  = get_tlv(fin, TRANSCRIPT);

        //Recompute HMAC over full transcript
        uint8_t mac_calc[MAC_SIZE];
        hmac(mac_calc, ts, ts_len);

        //Compare to what client sent
        if (memcmp(mac_calc, tr->val, MAC_SIZE) != 0) {
            exit(4);  // Bad transcript
        }

        //Handhsake complete, drop encrypted shit
        state_sec = DATA_STATE;
        free_tlv(fin);
        break;
    }
    case DATA_STATE: {
        //Unwrap DATA TLV, verify MAC, decrypt, output plaintext
        tlv* dt = deserialize_tlv(buf, length);
        tlv* ivt = get_tlv(dt, IV);
        tlv* cpt = get_tlv(dt, CIPHERTEXT);
        tlv* mct = get_tlv(dt, MAC);
        uint8_t* iv = ivt->val;
        uint8_t* cipher = cpt->val;
        size_t cipher_len = cpt->length;
        uint8_t mac_in[IV_SIZE + cipher_len];
        memcpy(mac_in, iv, IV_SIZE);
        memcpy(mac_in + IV_SIZE, cipher, cipher_len);
        uint8_t mac_calc[MAC_SIZE];
        hmac(mac_calc, mac_in, IV_SIZE + cipher_len);
        if (memcmp(mac_calc, mct->val, MAC_SIZE) != 0) exit(5);
        uint8_t plaintext[2048];
        size_t pt_len = decrypt_cipher(plaintext, cipher, cipher_len, iv);
        output_io(plaintext, pt_len);
        break;
        //Note that both sides are parsing the TLV here dude
        tlv* data = deserialize_tlv(buf, length);
        //Todo: extract IV, ciphertext, MAC; verify MAC, decrypt, pass plaintext to application
    }
    default:
        break;
    }
}

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
//WORK TO DO HERE GABE
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        // 1) Generate ephemeral key and nonce, build TLV, cache transcript
        //Picks a fresh, random EC private scalar d on the P-256 curve.
        //Under the hood it calls OpenSSL’s EVP_PKEY_keygen for an EC key.
        generate_private_key();
        //Computes the matching public point Q = d·G and DER-encodes it.
        //You end up with a uint8_t *public_key buffer of about 91 bytes (that DER blob) and pub_key_size telling you its length.
        derive_public_key();



        unit8_t nonce[NONCE_SIZE];
        //generate_nonce(...) fills a 32-byte array with cryptographically secure random bytes.
        generate_nonce(nonce, NONCE_SIZE);



        //create_tlv(type) allocates a new TLV node with that type byte.
        tlv* ch = create_tlv(CLIENT_HELLO);

        //add_val(tlv, data, len) turns that node into a leaf carrying len bytes of data.)
        tlv* n = create_tlv(NONCE);

        //(add_val) used only on leaf nodes)
        add_val(n, nonce, NONCE_SIZE);
        //Allocates a new TLV node with that type of data (Note that here we are working with, CLIENT_HELLO, NONCE, and PUBLIC_KEY)
        tlv *pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);

        //First emit teh nonce tlv, then emit the public key
        add_tlv(ch, n);
        add_tlv(ch, pk);

        ssize_t len = serialize_tlv(buf, ch);
        //Cache those very same bytes in your transcript buffer
        memcpy(ts + ts_len, buf, len);
        ts_len += len;
        // advance state to wait for ServerHello
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
        
        // print("SEND CLIENT HELLO"); //Debug log
        // client_hello = create_tlv(CLIENT_HELLO); //Build a TLV tree for ClientHello
        // return serialize_tlv(buf, client_hello); //Seralize it into buf and return length
    }
    case SERVER_SERVER_HELLO_SEND: {
        //Server side only, not used by client
        print("SEND SERVER HELLO");
        // TODO: construct server_hello TLV tree, derive transcript, then:
        // return serialize_tlv(buf, server_hello);
    }
    case CLIENT_FINISHED_SEND: {
        //Compute HMAC over the concatenated transcript
        uint8_t mac_val[MAC_SIZE];
        //Macval is 32 bytes long
        hmac(mac_val, ts, ts_len);
        //Build finished TLV
        tlv* fin = create_tlv(FINISHED);
        //Allocate a node of type TLV finsihed of size 30
        tlv* tr = create_tlv(TRANSCRIPT); 
        add_val(tr, mac_val, MAC_SIZE);
        //Build a leaf TLV of type 0x04 (Transcript), carrying the raw 32-byte HMAC you just computed.
        add_tlv(fin, tr);
        //Nest that Transcript TLV inside the Finished TLV. Now fin->length reflects the nested TLV's size plus it's own headers
        size_t len = serialize_tlv(buf, fin);
        //Transition your FSM into the "secure data phase"
        state_sec = DATA_STATE;
        return len;





        // print("SEND FINISHED");
        // TODO: build Finished TLV using HMAC transcript and:
        // return serialize_tlv(buf, finished_tlv);
    }
    case DATA_STATE: {
        // Data state: encrypt application data with libsecurity and wrap in DATA TLV
        uint8_t plaintext[1024]; 
        size_t pt_len = input_io(plaintext, sizeof, plaintext);
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
        //INORE FOR NOW, BUT CONFIDENT WE MUST COME BACK LATER
        //Client: parse ServerHello TLV
        // client_hello = deserialize_tlv(buf, length);
        //Todo: extract HMAC, recompute transcript HMAC, compare and exit(4) on mismatch
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        //Break up that ServerHello -> verify cert/signature -> derive keys -> work
        tlv* sh = deserialize_tlv(buf, length);
        // verify certificate chain, DNS name, handshake signature...
        // append raw bytes to transcript
        memcpy(ts + ts_len, buf, length); ts_len += length;
        derive_secret();
        derive_keys(ts, ts_len);
        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        // // Server: parse Finished TLV from client, verify HMAC of transcript
        // tlv* finished = deserialize_tlv(buf, length);
        // // TODO: extract HMAC, recompute transcript HMAC, compare and exit(4) on mismatch
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

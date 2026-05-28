#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <crypto/algapi.h>
#include <linux/crypto.h>
#include <linux/types.h>

typedef struct mkv_subkeys {
	uint64_t ek[16][2];
	uint64_t dk[16][2];
    uint64_t k_post[2];
} MKV_subkeys;
// Bảng S-box
static const unsigned char sbox[16][16] = {
    {0x01, 0x11, 0x91, 0xE1, 0xD1, 0xB1, 0x71, 0x61, 0xF1, 0x21, 0xC1, 0x51, 0xA1, 0x41, 0x31, 0x81},
    {0x00, 0x10, 0xE3, 0x92, 0xB5, 0xD4, 0x77, 0x66, 0x89, 0x38, 0xAB, 0x4A, 0xCD, 0x5C, 0x2F, 0xFE},
    {0x08, 0x5F, 0x3E, 0xB0, 0x1C, 0xC2, 0x83, 0xDD, 0xE8, 0xF6, 0x47, 0x79, 0x95, 0x2B, 0xAA, 0x64},
    {0x0F, 0x48, 0xD0, 0x29, 0xA3, 0x1A, 0xF2, 0xBB, 0x65, 0xCC, 0xE4, 0x3D, 0x57, 0x7E, 0x86, 0x9F},
    {0x0C, 0x2A, 0xF4, 0x1F, 0x5B, 0x90, 0xEE, 0xC5, 0x36, 0x6D, 0x73, 0x88, 0xBC, 0xA7, 0x49, 0xD2},
    {0x0A, 0x3C, 0x18, 0x85, 0xE0, 0x4D, 0x99, 0xA4, 0xB3, 0x5E, 0xDA, 0xC7, 0x72, 0xFF, 0x6B, 0x26},
    {0x06, 0x76, 0xCF, 0xA8, 0x4E, 0x59, 0x60, 0x17, 0xDC, 0x9B, 0x32, 0xF5, 0x23, 0x84, 0xED, 0xBA},
    {0x07, 0x67, 0x2D, 0x3B, 0xFA, 0x8C, 0x16, 0x70, 0x54, 0xA2, 0x98, 0xBE, 0xEF, 0xD9, 0xC3, 0x45},
    {0x0E, 0xA9, 0x62, 0x5A, 0x27, 0xBF, 0x34, 0x9C, 0xFD, 0xD5, 0x8E, 0xE6, 0x1B, 0x43, 0x78, 0xC0},
    {0x03, 0xB2, 0x87, 0xC4, 0x9D, 0x6E, 0x4B, 0xF8, 0x7A, 0xE9, 0x2C, 0xAF, 0xD6, 0x15, 0x50, 0x33},
    {0x0D, 0xFB, 0x56, 0xEC, 0x3F, 0x75, 0xB8, 0x42, 0x1E, 0x24, 0xC9, 0x93, 0x80, 0x6A, 0xD7, 0xAD},
    {0x04, 0xE5, 0xB9, 0x7D, 0x82, 0xA6, 0xCA, 0x2E, 0x97, 0x13, 0x6F, 0xDB, 0x44, 0x30, 0xFC, 0x58},
    {0x0B, 0x8D, 0x9A, 0x46, 0x74, 0x28, 0xDF, 0x53, 0xCB, 0xB7, 0xF0, 0x6C, 0xAE, 0xE2, 0x35, 0x19},
    {0x05, 0x94, 0x7B, 0xDE, 0xC6, 0xF3, 0xAC, 0x39, 0x4F, 0x8A, 0x55, 0x20, 0x68, 0xBD, 0x12, 0xE7},
    {0x02, 0xD3, 0xA5, 0xF7, 0x69, 0xEB, 0x5D, 0x8F, 0x22, 0x40, 0xB6, 0x14, 0x3A, 0xC8, 0x9E, 0x7C},
    {0x09, 0xCE, 0x4C, 0x63, 0xD8, 0x37, 0x25, 0xEA, 0xA0, 0x7F, 0x1D, 0x52, 0xF9, 0x96, 0xB4, 0x8B}
};

// bảng S-box đảo
static const unsigned char inverse_sbox[16][16] = {
    {0x10, 0x00, 0xE0, 0x90, 0xB0, 0xD0, 0x60, 0x70, 0x20, 0xF0, 0x50, 0xC0, 0x40, 0xA0, 0x80, 0x30},
    {0x11, 0x01, 0xDE, 0xB9, 0xEB, 0x9D, 0x76, 0x67, 0x52, 0xCF, 0x35, 0x8C, 0x24, 0xFA, 0xA8, 0x43},
    {0xDB, 0x09, 0xE8, 0x6C, 0xA9, 0xF6, 0x5F, 0x84, 0xC5, 0x33, 0x41, 0x2D, 0x9A, 0x72, 0xB7, 0x1E},
    {0xBD, 0x0E, 0x6A, 0x9F, 0x86, 0xCE, 0x48, 0xF5, 0x19, 0xD7, 0xEC, 0x73, 0x51, 0x3B, 0x22, 0xA4},
    {0xE9, 0x0D, 0xA7, 0x8D, 0xBC, 0x7F, 0xC3, 0x2A, 0x31, 0x4E, 0x1B, 0x96, 0xF2, 0x55, 0x64, 0xD8},
    {0x9E, 0x0B, 0xFB, 0xC7, 0x78, 0xDA, 0xA2, 0x3C, 0xBF, 0x65, 0x83, 0x44, 0x1D, 0xE6, 0x59, 0x21},
    {0x66, 0x07, 0x82, 0xF3, 0x2F, 0x38, 0x17, 0x71, 0xDC, 0xE4, 0xAD, 0x5E, 0xCB, 0x49, 0x95, 0xBA},
    {0x77, 0x06, 0x5C, 0x4A, 0xC4, 0xA5, 0x61, 0x16, 0x8E, 0x2B, 0x98, 0xD2, 0xEF, 0xB3, 0x3D, 0xF9},
    {0xAC, 0x0F, 0xB4, 0x26, 0x6D, 0x53, 0x3E, 0x92, 0x4B, 0x18, 0xD9, 0xFF, 0x75, 0xC1, 0x8A, 0xE7},
    {0x45, 0x02, 0x13, 0xAB, 0xD1, 0x2C, 0xFD, 0xB8, 0x7A, 0x56, 0xC2, 0x69, 0x87, 0x94, 0xEE, 0x3F},
    {0xF8, 0x0C, 0x79, 0x34, 0x57, 0xE2, 0xB5, 0x4D, 0x63, 0x81, 0x2E, 0x1A, 0xD6, 0xAF, 0xCC, 0x9B},
    {0x23, 0x05, 0x91, 0x58, 0xFE, 0x14, 0xEA, 0xC9, 0xA6, 0xB2, 0x6F, 0x37, 0x4C, 0xDD, 0x7B, 0x85},
    {0x8F, 0x0A, 0x25, 0x7E, 0x93, 0x47, 0xD4, 0x5B, 0xED, 0xAA, 0xB6, 0xC8, 0x39, 0x1C, 0xF1, 0x62},
    {0x32, 0x04, 0x4F, 0xE1, 0x15, 0x89, 0x9C, 0xAE, 0xF4, 0x7D, 0x5A, 0xBB, 0x68, 0x27, 0xD3, 0xC6},
    {0x54, 0x03, 0xCD, 0x12, 0x3A, 0xB1, 0x8B, 0xDF, 0x28, 0x99, 0xF7, 0xE5, 0xA3, 0x6E, 0x46, 0x7C},
    {0xCA, 0x08, 0x36, 0xD5, 0x42, 0x6B, 0x29, 0xE3, 0x97, 0xFC, 0x74, 0xA1, 0xBE, 0x88, 0x1F, 0x5D}
};

// Hàm tra cứu S-box
static unsigned char lookup_sbox(unsigned char input, int is_inv) {
    unsigned char row = (input & 0xF0) >> 4;
    unsigned char col = input & 0x0F;
    if(is_inv) return inverse_sbox[row][col];
    else return sbox[row][col];
}

// Hàm xử lý từng byte của mảng 128-bit
static void process_bytes(const unsigned char *in, int is_inv, unsigned char *out) {
    for (int i = 0; i < 16; i++) {
        out[i] = lookup_sbox(in[i], is_inv);
    }
}

// Hàm thực hiện phép nhân M2 trên một byte đầu vào
static uint8_t M2(uint8_t in) {
    unsigned char out = 0;
    out |= ((in >> 6) & 1) << 7; // M2[7] = in[6]
    out |= ((in >> 5) & 1) << 6; // M2[6] = in[5]
    out |= (((in >> 4) & 1) ^ ((in >> 7) & 1)) << 5; // M2[5] = in[4] ^ in[7]
    out |= ((in >> 3) & 1) << 4; // M2[4] = in[3]
    out |= (((in >> 2) & 1) ^ ((in >> 7) & 1)) << 3; // M2[3] = in[2] ^ in[7]
    out |= ((in >> 1) & 1) << 2; // M2[2] = in[1]
    out |= (((in >> 0) & 1) ^ ((in >> 7) & 1)) << 1; // M2[1] = in[0] ^ in[7]
    out |= ((in >> 7) & 1) << 0; // M2[0] = in[7]

    return out;
}

// Hàm Mix_column xử lý trên mảng đầu vào 16 byte
static void Mix_column(const unsigned char *in, unsigned char *out) {
    
    out[0] = in[0] ^ in[2] ^ in[3] ^ M2(in[1] ^ in[3]);
    out[1] = in[1] ^ in[3] ^ out[0] ^ M2(in[2] ^ out[0]);
    out[2] = in[2] ^ out[0] ^ out[1] ^ M2(in[3] ^ out[1]);
    out[3] = in[3] ^ out[1] ^ out[2] ^ M2(out[0] ^ out[2]);

    out[4] = in[4] ^ in[6] ^ in[7] ^ M2(in[5] ^ in[7]);
    out[5] = in[5] ^ in[7] ^ out[4] ^ M2(in[6] ^ out[4]);
    out[6] = in[6] ^ out[4] ^ out[5] ^ M2(in[7] ^ out[5]);
    out[7] = in[7] ^ out[5] ^ out[6] ^ M2(out[4] ^ out[6]);

    out[8] = in[8] ^ in[10] ^ in[11] ^ M2(in[9] ^ in[11]);
    out[9] = in[9] ^ in[11] ^ out[8] ^ M2(in[10] ^ out[8]);
    out[10] = in[10] ^ out[8] ^ out[9] ^ M2(in[11] ^ out[9]);
    out[11] = in[11] ^ out[9] ^ out[10] ^ M2(out[8] ^ out[10]);

    out[12] = in[12] ^ in[14] ^ in[15] ^ M2(in[13] ^ in[15]);
    out[13] = in[13] ^ in[15] ^ out[12] ^ M2(in[14] ^ out[12]);
    out[14] = in[14] ^ out[12] ^ out[13] ^ M2(in[15] ^ out[13]);
    out[15] = in[15] ^ out[13] ^ out[14] ^ M2(out[12] ^ out[14]);

}

// Hàm inv_mix_column xử lý trên mảng đầu vào 16 byte
static void inv_mix_column(const unsigned char *in, unsigned char *out) {
    
    out[3] = in[1] ^ in[2] ^ in[3] ^ M2(in[0] ^ in[2]);
    out[2] = in[0] ^ in[1] ^ in[2] ^ M2(in[1] ^ out[3]);
    out[1] = out[3] ^ in[0] ^ in[1] ^ M2(in[0] ^ out[2]);
    out[0] = in[0] ^ out[2] ^ out[3] ^ M2(out[1] ^ out[3]);

    out[7] = in[5] ^ in[6] ^ in[7] ^ M2(in[4] ^ in[6]);
    out[6] = in[4] ^ in[5] ^ in[6] ^ M2(in[5] ^ out[7]);
    out[5] = out[7] ^ in[4] ^ in[5] ^ M2(in[4] ^ out[6]);
    out[4] = in[4] ^ out[6] ^ out[7] ^ M2(out[5] ^ out[7]);

    out[11] = in[9] ^ in[10] ^ in[11] ^ M2(in[8] ^ in[10]);
    out[10] = in[8] ^ in[9] ^ in[10] ^ M2(in[9] ^ out[11]);
    out[9] = out[11] ^ in[8] ^ in[9] ^ M2(in[8] ^ out[10]);
    out[8] = in[8] ^ out[10] ^ out[11] ^ M2(out[9] ^ out[11]);

    out[15] = in[13] ^ in[14] ^ in[15] ^ M2(in[12] ^ in[14]);
    out[14] = in[12] ^ in[13] ^ in[14] ^ M2(in[13] ^ out[15]);
    out[13] = out[15] ^ in[12] ^ in[13] ^ M2(in[12] ^ out[14]);
    out[12] = in[12] ^ out[14] ^ out[15] ^ M2(out[13] ^ out[15]);

}
static void X_word(const unsigned char *in, unsigned char *out){
    out[0] = in[4] ^ in[8] ^ in[12];
    out[1] = in[5] ^ in[9] ^ in[13];
    out[2] = in[6] ^ in[10] ^ in[14];
    out[3] = in[7] ^ in[11] ^ in[15];
    out[4] = in[8] ^ in[12] ^ in[0];
    out[5] = in[9] ^ in[13] ^ in[1];
    out[6] = in[10] ^ in[14] ^ in[2];
    out[7] = in[11] ^ in[15] ^ in[3];
    out[8] = in[12] ^ in[0] ^ in[4];
    out[9] = in[13] ^ in[1] ^ in[5];
    out[10] = in[14] ^ in[2] ^ in[6];
    out[11] = in[15] ^ in[3] ^ in[7];
    out[12] = in[0] ^ in[4] ^ in[8];
    out[13] = in[1] ^ in[5] ^ in[9];
    out[14] = in[2] ^ in[6] ^ in[10];
    out[15] = in[3] ^ in[7] ^ in[11];
}

static void F(const unsigned char *in, const unsigned char *key1, const unsigned char *key2, unsigned char *out) {
    uint8_t b[16], b1[16], b2[16];
    // S1
    uint8_t temp1[16];
    for (int i = 0; i < 16; i++) {
        temp1[i] = in[i] ^ key1[i];
    }
    process_bytes(temp1, 0, b);
    // Mix_column
    Mix_column(b, b1);
    // S2
    uint8_t temp2[16];
    for (int i = 0; i < 16; i++) {
        temp2[i] = b1[i] ^ key2[i];
    }
    process_bytes(temp2, 0, b2);
    // XWord
    X_word(b2, out);
}

static void inF(const unsigned char *in, const unsigned char *key1, const unsigned char *key2, unsigned char *out){
    uint8_t b[16], b1[16], b2[16], b3[16];
    X_word(in, b);
    process_bytes(b, 1, b1);
    uint8_t temp1[16];
    for (int i = 0; i < 16; i++) {
        temp1[i] = b1[i] ^ key1[i];
    }
    inv_mix_column(temp1, b2);
    process_bytes(b2, 1, b3);
    for (int i = 0; i < 16; i++) {
        out[i] = b3[i] ^ key2[i];
    }
}
static void F_key(const unsigned char *key_left, const unsigned char *key_right, uint8_t const_val, unsigned char *out_left, unsigned char *out_right) {
    uint8_t tmpC[16] = {0};
    uint8_t CL[16] = {0};
    uint8_t CR[16] = {0};
    
    uint8_t tmp1[16], tmp2[16], tmp3[16], tmp4[16];
    // Initialize CL and CR
    CL[15] = const_val;
    CR[15] = const_val + 1;
    
    // Call function F with parameters
    F(key_left, CL, tmpC, tmp1);
    F(tmp1, tmpC, tmpC, tmp2);
    
    F(key_right, CR, tmpC, tmp3);
    F(tmp3, tmpC, tmpC, tmp4);
    
    // Compute out_left and out_right
    for (int i = 0; i < 16; i++) {
        out_right[i] = tmp4[i] ^ tmp2[i];
        out_left[i] = tmp4[i];
    }
}

static void mkv_wipe_key(MKV_subkeys *subkeys)
{
	int i;

	for (i = 15; i >= 0; i--) {
		subkeys->ek[i][0] = 0x0000000000000000;
		subkeys->ek[i][1] = 0x0000000000000000;
		subkeys->dk[i][0] = 0x0000000000000000;
		subkeys->dk[i][1] = 0x0000000000000000;
	}
}

static int mkv_set_key(struct crypto_tfm *tfm, const unsigned char *key, unsigned int keylen){ 

    MKV_subkeys *subkeys = crypto_tfm_ctx(tfm);
    unsigned char k0[32];
    int round = 0;
    if (keylen == 16)
    {
        for(int i = 0; i < 16; i++){
            k0[i] = key[i];
            k0[i+16] = ~key[i];
        }
        round = 6; 
    }else if (keylen == 24)
    {
        for(int i = 0; i < 24; i++) k0[i] = key[i];
        int c = 8;
        for(int i = 24; i < 32; i++){
            k0[i] = ~key[c];
            c++;
        }
        round = 7;
    }else if (keylen == 32)
    {
        for(int i = 0; i < 32; i++){
            k0[i] = key[i];
        }
        round = 8;
    }else
    {
		return -1;
	}
    
    uint64_t key_l[2], key_r[2];
    uint8_t cnst;
    mkv_wipe_key(subkeys);

    key_l[0] = ((uint64_t *) k0)[0];
	key_l[1] = ((uint64_t *) k0)[1];
	key_r[0] = ((uint64_t *) k0)[2];
	key_r[1] = ((uint64_t *) k0)[3];
    
    subkeys->ek[0][0] = key_l[0];
	subkeys->ek[0][1] = key_l[1];
    subkeys->dk[round*2-1][0] = key_l[0];
	subkeys->dk[round*2-1][1] = key_l[1];
    for (int i = 1; i <= round; i++)
    {
        cnst = 1 + 2*(i-1);
        F_key((unsigned char *)key_l, (unsigned char *)key_r, cnst, (unsigned char *)key_l, (unsigned char *)key_r);

        if (i < round)
        {
            subkeys->ek[i*2-1][0] = key_l[0];
            subkeys->ek[i*2-1][1] = key_l[1];
            subkeys->ek[i*2][0] = key_r[0];
            subkeys->ek[i*2][1] = key_r[1];
            subkeys->dk[(round-i)*2][0] = subkeys->ek[i*2-1][0];
		    subkeys->dk[(round-i)*2][1] = subkeys->ek[i*2-1][1];
            subkeys->dk[(round-i)*2-1][0] = subkeys->ek[i*2][0];
		    subkeys->dk[(round-i)*2-1][1] = subkeys->ek[i*2][1];
        }else{
            subkeys->ek[i*2-1][0] = key_l[0];
            subkeys->ek[i*2-1][1] = key_l[1];
            subkeys->dk[(round-i)*2][0] = subkeys->ek[i*2-1][0];
		    subkeys->dk[(round-i)*2][1] = subkeys->ek[i*2-1][1];
            subkeys->k_post[0] = key_r[0];
            subkeys->k_post[1] = key_r[1];
        }
        
    }
    return 0;
}

static void mkv_encrypt(struct crypto_tfm *tfm, unsigned char *out,
			const unsigned char *in){

    MKV_subkeys *subkeys = crypto_tfm_ctx(tfm);
    uint8_t x[16] = {0}; 
    uint8_t kl[16] = {0};
    uint8_t kr[16] = {0};
    uint64_t isBreak[2];  
    for (int i = 0; i < 16; i++)
    {
        x[i] = ((uint8_t *)in)[i];
    }
    for (int i = 0; i < 8; i++)
    {
        isBreak[0] = subkeys->ek[i*2][0];
        isBreak[1] = subkeys->ek[i*2][1];
        if(isBreak[0] == 0 && isBreak[1] == 0) break;
        for (int j = 0; j < 16; j++)
        {
            kl[j] = ((uint8_t *)subkeys->ek[i*2])[j];
            kr[j] = ((uint8_t *)subkeys->ek[i*2+1])[j];
        }
        F(x,kl,kr, x);
    }
    for (int i = 0; i < 16; i++)
    {
        ((uint8_t *) out)[i] = x[i] ^ ((uint8_t *)subkeys->k_post)[i];
    }
    
    
}

static void mkv_decrypt(struct crypto_tfm *tfm, unsigned char *out,
			const unsigned char *in){
    
    MKV_subkeys *subkeys = crypto_tfm_ctx(tfm);
    uint8_t x[16] = {0}; 
    uint8_t kl[16] = {0};
    uint8_t kr[16] = {0};
    uint64_t isBreak[2];
    for (int i = 0; i < 16; i++)
    {
        x[i] = ((uint8_t *)in)[i];
    }
    for (int i = 0; i < 16; i++)
    {
        out[i] = x[i] ^ ((uint8_t *)subkeys->k_post)[i];
    }
    for (int i = 0; i < 8; i++)
    {
        isBreak[0] = subkeys->dk[i*2][0];
        isBreak[1] = subkeys->dk[i*2][1];
        if(isBreak[0] == 0 && isBreak[1] == 0) break;
        for (int j = 0; j < 16; j++)
        {
            kl[j] = ((uint8_t *)subkeys->dk[i*2])[j];
            kr[j] = ((uint8_t *)subkeys->dk[i*2+1])[j];
        }
        inF(out, kl, kr, out);
    }
}

static struct crypto_alg mkv_alg = {
	.cra_name		=	"mkv128",
	.cra_driver_name	=	"mkv-generic",
	.cra_priority		=	111,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	16,
	.cra_ctxsize		=	sizeof(MKV_subkeys),
	.cra_alignmask		=	3,
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{ .cipher = {
	.cia_min_keysize	=	16,
	.cia_max_keysize	=	32,
	.cia_setkey		= 	mkv_set_key,
	.cia_encrypt		=	mkv_encrypt,
	.cia_decrypt		=	mkv_decrypt } }
};

static int __init mkv_mod_init(void)
{
	return crypto_register_alg(&mkv_alg);
}

static void __exit mkv_mod_fini(void)
{
	crypto_unregister_alg(&mkv_alg);
}

module_init(mkv_mod_init);
module_exit(mkv_mod_fini);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("128bit cipher as specified in MKV");
MODULE_ALIAS_CRYPTO("mkv128");

#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"

/* script args errors */
#define ERROR_INVALID_PUBKEYS_CNT -42
#define ERROR_INVALID_THRESHOLD -43
#define ERROR_INVALID_REQUIRE_FIRST_N -44
/* verification errors */
#define ERROR_MULTSIG_SCRIPT_HASH -51
#define ERROR_VERIFICATION -52

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define MAX_SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define FLAGS_SIZE 4

/*
 * Arguments:
 * multisig script blake160 hash, 20 bytes.
 *
 * Witness:
 * multisig_script | Signature1 | signature2 | ...
 * multisig_script: S | R | M | N | Pubkey1 | Pubkey2 | ...
 *
 * +------------+----------------------------------+-------+
 * |            |           Description            | Bytes |
 * +------------+----------------------------------+-------+
 * | S          | reserved for future use          |     1 |
 * | R          | first nth public keys must match |     1 |
 * | M          | threshold                        |     1 |
 * | N          | total public keys                |     1 |
 * | PubkeyN    | compressed pubkey                |    33 |
 * | SignatureN | recoverable signature            |    65 |
 * +------------+----------------------------------+-------+
 *
 */

int main() {
  int ret;
  uint64_t len;
  unsigned char temp[TEMP_SIZE];

  /* Load args */
  unsigned char script[MAX_SCRIPT_SIZE];
  len = MAX_SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Check witnesses is less than or equals to inputs  */
  ret = check_witnesses_len();
  if (ret != CKB_SUCCESS) {
    return ERROR_INVALID_WITNESSES_COUNT;
  }

  /* Load witness of first input */
  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, witness_len, &lock_bytes_seg);
  if (lock_bytes_seg.size < FLAGS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  unsigned char lock_bytes[lock_bytes_seg.size];
  uint64_t lock_bytes_len = lock_bytes_seg.size;
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_len);

  /* Get flags */
  uint8_t pubkeys_cnt = lock_bytes[3];
  uint8_t threshold = lock_bytes[2];
  uint8_t require_first_n = lock_bytes[1];
  if (pubkeys_cnt == 0) {
    return ERROR_INVALID_PUBKEYS_CNT;
  }
  if (threshold > pubkeys_cnt) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (threshold == 0) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (require_first_n > threshold) {
    return ERROR_INVALID_REQUIRE_FIRST_N;
  }
  size_t multisig_script_len = FLAGS_SIZE + PUBKEY_SIZE * pubkeys_cnt;
  size_t signatures_len = SIGNATURE_SIZE * threshold;
  size_t required_lock_len = multisig_script_len + signatures_len;
  if (lock_bytes_len != required_lock_len) {
    return ERROR_WITNESS_SIZE;
  }

  /* Check multisig script hash */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(args_bytes_seg.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_MULTSIG_SCRIPT_HASH;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  /* Set signature to zero, then digest the first witness */
  memset((void *)(lock_bytes_seg.ptr + multisig_script_len), 0, signatures_len);
  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, witness, witness_len);

  /* Digest other witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Verify threshold signatures */
  uint8_t used_signatures[threshold];
  memset(used_signatures, 0, threshold);

  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  for (size_t i = 0; i < threshold; i++) {
    /* Load signature */
    secp256k1_ecdsa_recoverable_signature signature;
    size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, &lock_bytes[signature_offset],
            lock_bytes[signature_offset + RECID_INDEX]) == 0) {
      return ERROR_SECP_PARSE_SIGNATURE;
    }

    /* Recover pubkey */
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
      return ERROR_SECP_RECOVER_PUBKEY;
    }

    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    /* Check pubkeys */
    uint8_t matched = 0;
    for (size_t i = 0; i < pubkeys_cnt; i++) {
      if (used_signatures[i] == 1) {
        continue;
      }
      if (memcmp(&lock_bytes[FLAGS_SIZE + i * PUBKEY_SIZE], temp,
                 PUBKEY_SIZE) != 0) {
        continue;
      }
      matched = 1;
      used_signatures[i] = 1;
      break;
    }

    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  for (size_t i = 0; i < require_first_n; i++) {
    if (used_signatures[i] != 1) {
      return ERROR_VERIFICATION;
    }
  }

  return 0;
}

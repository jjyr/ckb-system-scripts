/* UDT wallet lock script
 * Cells with this script as the lock is a wallet cell.
 *
 * Wallet cell can be unlocked without a signature, if:
 *
 * 1. There is 1 output wallet cell that has the same type hash with the
 * unlocked wallet cell.
 * 2. The UDT or CKB(if type script is none) in the output wallet is more than
 * the unlocked wallet.
 * 3. if the type script is none, the cell data is empty.
 *
 * otherwise, the script perform secp256k1_blake160_sighash_all verification.
 */

#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "lock_utils.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768
#define CKB_LEN 8
#define UDT_LEN 16

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OVERFLOWING -51
#define ERROR_AMOUNT -52

typedef unsigned __int128 uint128_t;

int pass_through() {
  unsigned char lock_hash[BLAKE2B_BLOCK_SIZE];
  unsigned char type_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  /* load wallet lock hash */
  int ret = ckb_load_script_hash(lock_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  len = BLAKE2B_BLOCK_SIZE;
  /* load wallet type hash */
  ret = ckb_checked_load_cell_by_field(
      type_hash, &len, 0, 0, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_TYPE_HASH);

  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  int output_wallet_i = 0;
  int has_output_wallet = 0;
  size_t i = 0;
  while (1) {
    uint8_t lock_hash_buf[BLAKE2B_BLOCK_SIZE];
    uint8_t type_hash_buf[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(
        lock_hash_buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(
        type_hash_buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    if ((memcmp(lock_hash_buf, lock_hash, BLAKE2B_BLOCK_SIZE) == 0) ||
        (memcmp(type_hash_buf, type_hash, BLAKE2B_BLOCK_SIZE) == 0)) {
      /* duplicates output wallet, return false */
      if (has_output_wallet) {
        return 0;
      }
      output_wallet_i = i;
      has_output_wallet = 1;
    }
    i += 1;
  }

  /* can't pass through */
  if (!has_output_wallet) {
    return 0;
  }

  /* check wallet token type */
  unsigned char buf[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_checked_load_cell_by_field(buf, &len, 0, 0, CKB_SOURCE_GROUP_INPUT,
                                       CKB_CELL_FIELD_TYPE);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)buf;
  script_seg.size = len;
  int is_ckb = MolReader_ScriptOpt_is_none(&script_seg);

  /* ckb wallet can't has data */
  if (is_ckb) {
    len = 1;
    ckb_load_cell_data(buf, &len, 0, output_wallet_i, CKB_SOURCE_OUTPUT);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > 0) {
      return 0;
    }
  }

  /* check amount */
  if (is_ckb) {
    uint64_t input = 0;
    uint64_t output = 0;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&input, &len, 0, 0,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_OCCUPIED_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&output, &len, 0,
                                         output_wallet_i, CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_OCCUPIED_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > CKB_LEN) {
      return ERROR_ENCODING;
    }
    return output > input;
  } else {
    uint128_t input = 0;
    uint128_t output = 0;
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&input, &len, 0, 0,
                             CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = CKB_LEN;
    ret = ckb_load_cell_data((uint8_t *)&output, &len, 0, output_wallet_i,
                             CKB_SOURCE_OUTPUT);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > CKB_LEN) {
      return ERROR_ENCODING;
    }
    return output > input;
  }
}

int main() {
  if (pass_through()) {
    return 0;
  }
  return verify_secp256k1_blake160_sighash_all();
}

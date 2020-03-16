/* UDT anyone-can-pay lock script
 * For simplify, we call a cell with anyone-can-pay lock a wallet cell.
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
#define MAX_WITNESS_SIZE 32768
#define MAX_TYPE_HASH 256

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OVERFLOWING -51
#define ERROR_AMOUNT_NOT_ENOUGH -52
#define ERROR_TOO_MUCH_TYPE_HASH_INPUTS -53
#define ERROR_PARING_INPUT_FAILED -54
#define ERROR_PARING_OUTPUT_FAILED -55
#define ERROR_DUPLICATED_INPUT_TYPE_HASH -56
#define ERROR_DUPLICATED_OUTPUT_TYPE_HASH -57

typedef unsigned __int128 uint128_t;

typedef struct {
  int is_ckb_only;
  unsigned char type_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t ckb_amount;
  uint128_t udt_amount;
  uint32_t output_cnt;
} InputWallet;

int check_payment_unlock() {
  unsigned char lock_hash[BLAKE2B_BLOCK_SIZE];
  InputWallet input_wallets[MAX_TYPE_HASH];
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  /* load wallet lock hash */
  int ret = ckb_load_script_hash(lock_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  uint64_t min_ckb_amount = 0;
  uint128_t min_udt_amount = 0;

  /* iterate inputs and find input wallet cell */
  int i = 0;
  len = BLAKE2B_BLOCK_SIZE;
  while (1) {
    if (i >= MAX_TYPE_HASH) {
      return ERROR_TOO_MUCH_TYPE_HASH_INPUTS;
    }

    ret = ckb_checked_load_cell_by_field(input_wallets[i].type_hash, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    input_wallets[i].is_ckb_only = ret == CKB_ITEM_MISSING;
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }

    /* load amount */
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field(
        (uint8_t *)&input_wallets[i].ckb_amount, &len, 0, i,
        CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&input_wallets[i].udt_amount, &len, 0,
                             0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (input_wallets[i].is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len != UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    i++;
  }

  int input_wallets_cnt = i;

  /* iterate outputs wallet cell */
  i = 0;
  while (1) {
    uint8_t output_lock_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t output_type_hash[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    /* check lock hash */
    ret = ckb_checked_load_cell_by_field(output_lock_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int has_same_lock =
        memcmp(output_lock_hash, lock_hash, BLAKE2B_BLOCK_SIZE) == 0;
    if (!has_same_lock) {
      i++;
      continue;
    }
    /* load type hash */
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(output_type_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int is_ckb_only = ret == CKB_ITEM_MISSING;

    /* load amount */
    uint64_t ckb_amount;
    uint128_t udt_amount;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&ckb_amount, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&udt_amount, &len, 0, 0,
                             CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len != UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    /* find input wallet which has same type hash */
    int found_inputs = 0;
    for (int j = 0; j < input_wallets_cnt; j++) {
      int has_same_type = 0;
      /* check type hash */
      if (is_ckb_only) {
        has_same_type = input_wallets[j].is_ckb_only;
      } else {
        has_same_type = memcmp(output_type_hash, input_wallets[j].type_hash,
                               BLAKE2B_BLOCK_SIZE) == 0;
      }
      if (!has_same_type) {
        continue;
      }
      /* compare amount */
      if (ckb_amount < input_wallets[j].ckb_amount + min_ckb_amount) {
        return ERROR_AMOUNT_NOT_ENOUGH;
      }
      if (udt_amount < input_wallets[j].udt_amount + min_udt_amount) {
        return ERROR_AMOUNT_NOT_ENOUGH;
      }

      /* increase counter */
      found_inputs++;
      input_wallets[j].output_cnt += 1;
      if (found_inputs > 1) {
        return ERROR_DUPLICATED_INPUT_TYPE_HASH;
      }
      if (input_wallets[j].output_cnt > 1) {
        return ERROR_DUPLICATED_OUTPUT_TYPE_HASH;
      }
    }

    /* one output should pair with one input */
    if (found_inputs == 0) {
      return ERROR_PARING_OUTPUT_FAILED;
    } else if (found_inputs > 1) {
      return ERROR_DUPLICATED_INPUT_TYPE_HASH;
    }

    i ++;
  }

  /* check inputs wallet, one input should pair with one output */
  for (int j = 0; j < input_wallets_cnt; j++) {
    if (input_wallets[j].output_cnt == 0) {
      return ERROR_PARING_INPUT_FAILED;
    } else if (input_wallets[j].output_cnt > 1) {
      return ERROR_DUPLICATED_OUTPUT_TYPE_HASH;
    }
  }

  return CKB_SUCCESS;
}

int has_signature(int *has_sig) {
  int ret;
  unsigned char temp[MAX_WITNESS_SIZE];

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND && ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  *has_sig = ret == CKB_SUCCESS;
  return CKB_SUCCESS;
}

int main() {
  int ret;
  int has_sig;
  ret = has_signature(&has_sig);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (has_sig) {
    /* unlock via signature */
    return verify_secp256k1_blake160_sighash_all();
  } else {
    /* unlock via payment */
    return check_payment_unlock();
  }
}

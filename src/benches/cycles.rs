#[macro_use]
extern crate criterion;

use criterion::Criterion;
use super::{
    blake160, sign_tx, sign_tx_by_input_group, DummyDataLoader, MAX_CYCLES, SECP256K1_DATA_BIN,
    SIGHASH_ALL_BIN,
};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng, SeedableRng};

fn test_sighash_all_2_in_2_out_cycles() {

    let mut data_loader = DummyDataLoader::new();
    let mut generator = Generator::non_crypto_safe_prng(42);
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

    // key1
    let privkey = generator.gen_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    // key2
    let privkey2 = generator.gen_privkey();
    let pubkey2 = privkey2.pubkey().expect("pubkey");
    let pubkey_hash2 = blake160(&pubkey2.serialize());

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![(pubkey_hash, 1), (pubkey_hash2, 1)],
        &mut rng,
    );
    let tx = sign_tx_by_input_group(tx, &privkey, 0, 1);
    let tx = sign_tx_by_input_group(tx, &privkey2, 1, 1);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_cycles(c: &mut Criterion) {
    const CONSUME_CYCLES: u64 = 3394652;
    let mut group = c.benchmark_group("consume cycles");
    group.throughput(Throughput::Elements(CONSUME_CYCLES));
    group.bench_function("Consume cycles", |b| {
        b.iter(||test_sighash_all_2_in_2_out_cycles())
    });
}

criterion_group!(benches, test_cycles);
criterion_main!(benches);

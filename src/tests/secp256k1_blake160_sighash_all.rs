use super::{sign_tx, DummyDataLoader, MAX_CYCLES, SIGHASH_ALL_BIN};
use ckb_core::{
    cell::{CellMetaBuilder, ResolvedOutPoint, ResolvedTransaction},
    script::Script,
    transaction::{CellInput, CellOutput, OutPoint, Transaction, TransactionBuilder},
    Bytes, Capacity,
};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use numext_fixed_hash::H256;
use rand::{thread_rng, Rng};

fn gen_tx(dummy: &mut DummyDataLoader, script_data: Bytes, lock_args: Vec<Bytes>) -> Transaction {
    let previous_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let previous_index = 0;
    let capacity = Capacity::shannons(42);
    let previous_out_point = OutPoint::new_cell(previous_tx_hash, previous_index);
    let contract_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let contract_index = 0;
    let contract_out_point = OutPoint::new_cell(contract_tx_hash.clone(), contract_index);
    // dep contract code
    let dep_cell = CellOutput::new(
        Capacity::bytes(script_data.len()).expect("script capacity"),
        script_data,
        Default::default(),
        None,
    );
    let dep_cell_data_hash = dep_cell.data_hash();
    dummy
        .cells
        .insert(contract_out_point.clone().cell.unwrap(), dep_cell);
    // input unlock script
    let previous_output_cell = CellOutput::new(
        capacity,
        Default::default(),
        Script::new(lock_args, dep_cell_data_hash),
        None,
    );
    dummy.cells.insert(
        previous_out_point.clone().cell.unwrap(),
        previous_output_cell,
    );
    TransactionBuilder::default()
        .input(CellInput::new(previous_out_point.clone(), 0))
        .dep(contract_out_point)
        .output(CellOutput::new(
            capacity,
            Default::default(),
            Default::default(),
            None,
        ))
        .build()
}

fn sign_tx_hash(tx: Transaction, key: &Privkey, tx_hash: &[u8]) -> Transaction {
    // calculate message
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(tx_hash);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    TransactionBuilder::from_transaction(tx)
        .witness(vec![Bytes::from(sig.serialize())])
        .build()
}

fn build_resolved_tx<'a>(tx: &'a Transaction, data_size: usize) -> ResolvedTransaction<'a> {
    let previous_out_point = tx.inputs()[0].previous_output.clone();
    let deps_out_point = tx.deps()[0].clone();
    let capacity = tx.outputs()[0].capacity;
    let dep_cell = CellMetaBuilder::default()
        .out_point(deps_out_point.clone().cell.unwrap())
        .capacity(Capacity::bytes(data_size).expect("script capacity"))
        .build();
    let input_cell = CellMetaBuilder::default()
        .out_point(previous_out_point.clone().cell.unwrap())
        .capacity(capacity)
        .build();
    ResolvedTransaction {
        transaction: tx,
        resolved_deps: vec![ResolvedOutPoint::cell_only(dep_cell)],
        resolved_inputs: vec![ResolvedOutPoint::cell_only(input_cell)],
    }
}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&tx, SIGHASH_ALL_BIN.len());
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let wrong_privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = sign_tx(tx, &wrong_privkey);
    let resolved_tx = build_resolved_tx(&tx, SIGHASH_ALL_BIN.len());
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-3)));
}

#[test]
fn test_signing_wrong_tx_hash() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = {
        let mut rand_tx_hash = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut rand_tx_hash);
        sign_tx_hash(tx, &privkey, &rand_tx_hash[..])
    };
    let resolved_tx = build_resolved_tx(&tx, SIGHASH_ALL_BIN.len());
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-3)));
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );

    let mut buffer: Vec<u8> = vec![];
    buffer.resize(40000, 1);
    let super_long_message = Bytes::from(&buffer[..]);

    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx.hash()[..]);
    blake2b.update(&super_long_message[..]);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = privkey.sign_recoverable(&message).expect("sign");
    let tx = TransactionBuilder::from_transaction(tx)
        .witness(vec![Bytes::from(sig.serialize()), super_long_message])
        .build();

    let resolved_tx = build_resolved_tx(&tx, SIGHASH_ALL_BIN.len());
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-12)));
}
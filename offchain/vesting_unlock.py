from pycardano import (
    BlockFrostChainContext,
    PaymentSigningKey,
    PaymentVerificationKey,
    Address,
    PlutusV2Script,
    PlutusData,
    Redeemer,
    ScriptHash,
    Network,
    TransactionBuilder,
    UTxO,
)
from pycardano.hash import (
    TransactionId,
    ScriptHash,
)
import os, json, time
from dataclasses import dataclass
from typing import List
    
@dataclass
class VestingDatum(PlutusData):
    lock_until: int  # this is POSIX time, you can check and set it here: https://www.unixtimestamp.com
    owner: bytes  # we can pass owner's verification key hash as bytes
    beneficiary: bytes  # we can beneficiary's hash as bytes



def read_validator() -> dict:
    with open("../plutus.json", "r") as f:
        validator = json.load(f)
    script_bytes = PlutusV2Script(
        bytes.fromhex(validator["validators"][0]["compiledCode"])
    )
    script_hash = ScriptHash(bytes.fromhex(validator["validators"][0]["hash"]))
    return {
        "type": "PlutusV2",
        "script_bytes": script_bytes,
        "script_hash": script_hash,
    }


def validator_to_address(validator_hash: ScriptHash) -> Address:
    return Address(
        payment_part=validator_hash,
        network=Network.TESTNET,
    )
    

def unlock(
    utxos: List[UTxO],
    from_script: PlutusV2Script,
    sk: PaymentSigningKey,
    vk: PaymentVerificationKey,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("beneficiary.addr", "r") as f:
        beneficiary_address = Address.from_primitive(f.read())
    
    # build transaction
    builder = TransactionBuilder(context=context)
    for utxo in utxos:
        builder.add_script_input(
            utxo=utxo,
            script=from_script,
            redeemer=Redeemer(PlutusData()), # we don't have any redeemer in our contract but it needs to be empty
        )
    builder.add_input_address(beneficiary_address)
    builder.required_signers = [vk.hash()]
    signed_tx = builder.build_and_sign(
        signing_keys=[sk],
        change_address=beneficiary_address,
        auto_validity_start_offset=0, # set validity start to current slot
        auto_ttl_offset=2*60*60, # add two hours (TTL: time to live in slots == seconds)
    )
    
    # submit transaction
    return context.submit_tx(signed_tx)


context = BlockFrostChainContext(
    project_id=os.environ["BLOCKFROST_API_KEY"],
    base_url="https://cardano-preprod.blockfrost.io/api/",
)

sk = PaymentSigningKey.load("beneficiary.skey")
vk = PaymentVerificationKey.from_signing_key(sk)
validator = read_validator()

script_address = validator_to_address(validator["script_hash"])
script_utxos = context.utxos(script_address)
current_time = int(time.time()*1000)

# we filter out all the UTXOs by beneficiary and lock_until
utxos = []
for utxo in script_utxos:
    datum_cbor = utxo.output.datum.cbor
    if datum_cbor is not None:    
        datum = VestingDatum.from_cbor(datum_cbor)
        if datum.beneficiary.hex() == str(vk.hash()) and datum.lock_until <= current_time:
            utxos.append(utxo)

if not utxos:
    print("No redeemable utxo found. You need to wait a little longer...")
    exit(0)

tx_unlock = unlock(
    utxos=utxos,
    from_script=validator["script_bytes"],
    sk=sk,
    vk=vk,
    context=context,
)

print(
    f"2 tADA recovered from the contract:\n\tTx ID: {tx_unlock}"
)

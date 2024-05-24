from pycardano import (
    BlockFrostChainContext,
    PaymentSigningKey,
    PaymentVerificationKey,
    Address,
    PlutusV2Script,
    PlutusData,
    ScriptHash,
    Network,
    TransactionBuilder,
    TransactionOutput,
)
from pycardano.hash import (
    TransactionId,
    ScriptHash,
)
import os, json
from dataclasses import dataclass

    
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
    

def lock(
    lovelace: int,
    into: ScriptHash,
    datum: PlutusData,
    sk: PaymentSigningKey,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("owner.addr", "r") as f:
        owner_address = Address.from_primitive(f.read())
    contract_address = validator_to_address(into)
    
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_input_address(owner_address)
    builder.add_output(
        TransactionOutput(
            address=contract_address,
            amount=lovelace,
            datum=datum,
        )
    )
    signed_tx = builder.build_and_sign(
        signing_keys=[sk],
        change_address=owner_address,
    )

    # submit transaction
    return context.submit_tx(signed_tx)


context = BlockFrostChainContext(
    project_id=os.environ["BLOCKFROST_API_KEY"],
    base_url="https://cardano-preprod.blockfrost.io/api/",
)

sk = PaymentSigningKey.load("owner.skey")
vk = PaymentVerificationKey.from_signing_key(sk)
validator = read_validator()

owner_public_key_hash = vk.hash()
with open("beneficiary.addr", "r") as f:
    beneficiary_public_key_hash = Address.from_primitive(f.read()).payment_part

datum = VestingDatum(
    #lock_until=1672843961000,  #  Wed Jan 04 2023 14:52:41 GMT+0000
    lock_until=1698259500000,  #  Wed Jan 04 2023 14:52:41 GMT+0000
    owner=owner_public_key_hash.to_primitive(),  # our own wallet verification key hash
    beneficiary=beneficiary_public_key_hash.to_primitive(),
)

tx_hash = lock(
    lovelace=2_000_000,
    into=validator["script_hash"],
    datum=datum,
    sk=sk,
    context=context,
)
print(
    f"2 tADA locked into the contract at:\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)

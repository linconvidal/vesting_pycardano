from pycardano import Address, Network, PaymentSigningKey, PaymentVerificationKey

network = Network.TESTNET

owner_signing_key = PaymentSigningKey.generate()
owner_signing_key.save("owner.skey")
owner_verification_key = PaymentVerificationKey.from_signing_key(owner_signing_key)
owner_address = Address(payment_part=owner_verification_key.hash(), network=network)
with open("owner.addr", "w") as f:
    f.write(str(owner_address))

beneficiary_signing_key = PaymentSigningKey.generate()
beneficiary_signing_key.save("beneficiary.skey")
beneficiary_verification_key = PaymentVerificationKey.from_signing_key(
    beneficiary_signing_key
)
beneficiary_address = Address(
    payment_part=beneficiary_verification_key.hash(), network=network
)
with open("beneficiary.addr", "w") as f:
    f.write(str(beneficiary_address))

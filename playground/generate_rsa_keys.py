from Crypto.PublicKey import RSA

new_key = RSA.generate(2048)

public_key = new_key.publickey().exportKey("PEM")
private_key = new_key.exportKey("PEM")

with open("private_key.pem", "wb") as f:
    f.write(private_key)

with open("public_key.pem", "wb") as f:
    f.write(public_key)

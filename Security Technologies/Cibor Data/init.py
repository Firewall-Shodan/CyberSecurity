from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# geração da chave privada

priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# geração da chave publica
pub_key = priv_key.public_key()

# serialização das chaves privadas e públicas

pem_priv_key = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

pem_pub_key = priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

#   escrever a chave privada no arquivo private_key.pem

with open("private_key.pem", "wb") as f:
    f.write(pem_priv_key)

# escrever a chave publica no arquivo public_key.pem

with open("public_key.pem", "wb") as f:
    f.write(pem_pub_key)

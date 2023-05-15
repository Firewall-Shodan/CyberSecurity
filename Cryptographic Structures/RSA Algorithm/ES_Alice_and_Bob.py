from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Gerando parâmetros para troca de chaves DH
parametros = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Gerando as chaves pública e privada da Alice
chave_privada_alice = parametros.generate_private_key()
chave_pulica_alice = chave_privada_alice.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Gerando as chaves pública e privada do Bob
chave_privada_bob = parametros.generate_private_key()
chave_pulica_bob = chave_privada_bob.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Alice envia sua chave pública para Bob e vice-versa
# Aqui, apenas atribuímos as chaves públicas às variáveis
alice_recebe_chave = chave_pulica_bob
bob_recebe_chave = chave_pulica_alice

# Desserializar as chaves públicas
alice_recebe_chave = serialization.load_pem_public_key(alice_recebe_chave, backend=default_backend())
bob_recebe_chave = serialization.load_pem_public_key(bob_recebe_chave, backend=default_backend())

# Alice calcula a chave secreta compartilhada
alice_chave_partilhada = chave_privada_alice.exchange(alice_recebe_chave)

# Bob calcula a chave secreta compartilhada
bob_chave_partilhada = chave_privada_bob.exchange(bob_recebe_chave)

# Verificando se ambas as partes calcularam a mesma chave secreta compartilhada
assert alice_chave_partilhada == bob_chave_partilhada

# Derivando uma chave de sessão da chave secreta compartilhada usando HKDF
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'chave_s',
    backend=default_backend()
)
chave_s = hkdf.derive(alice_chave_partilhada)

# Criptografar uma mensagem usando a chave de sessão

messagem = b'Seja Bem-Vindo a UC de Engenharia de Seguranca Bob'

nonce = os.urandom(16)

cifra = Cipher(algorithms.AES(chave_s), modes.CTR(nonce), backend=default_backend())
encriptador = cifra.encryptor()
mensagem_criptografada = encriptador.update(messagem) + encriptador.finalize()

# Bob descriptografa a mensagem usando a chave de sessão
cifra = Cipher(algorithms.AES(chave_s), modes.CTR(nonce), backend=default_backend())
decriptador = cifra.decryptor()
mensagem_descriptografada = decriptador.update(mensagem_criptografada) + decriptador.finalize()

print(" ***************************************** ")
print("")
print("Mensagem Original:", messagem)
print("")
print("Mensagem Criptografada: ", mensagem_criptografada)
print("")
print(" Mensagem Descriptografada: ", mensagem_descriptografada)

# Verificando se a mensagem descriptografada é igual à mensagem original

assert mensagem_descriptografada == messagem

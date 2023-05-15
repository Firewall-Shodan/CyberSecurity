import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes



# Carregar a Chave privada do ficheiro private_key.pem

with open("private_key.pem", "rb") as f:
    pem_priv_key = f.read()
    priv_key = serialization.load_pem_private_key(
        pem_priv_key,
        password=None,
    )

# Carregar a Chave privada do ficheiro private_key.pem

with open("public_key.pem", "rb") as f:
    pem_pub_key = f.read()
    pub_key = serialization.load_pem_public_key(
        pem_pub_key,
    )
    serialized_pub_key = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Carregar os dados do document.cbor no formato cbor

with open('document.cbor', 'rb') as f:
    deserialized_data = cbor2.load(f)


# Função para Validar os PIDs,  retorna os Dados ou TRUE se os PIDs forem validados com sucesso.

def test_document():
    try:
        if "EAA" in deserialized_data:
            campos = ['emissora', 'data_emissao', 'validade',
                      'veiculo', 'info_pessoal', 'seguro']
            for campo in campos:
                if campo not in deserialized_data['EAA']:
                    return " Dados Inválidos "

            vc = ['marca', 'modelo', 'ano', 'matricula']
            for c in vc:
                if c not in deserialized_data['EAA']['veiculo']:
                    return " Dados Inválidos "

            ip = ['nome', 'data_nascimento', 'endereco']
            for c in ip:
                if c not in deserialized_data['EAA']['info_pessoal']:
                    return " Dados Inválidos "

            sc = ['numero_apolice', 'seguradora']
            for c in sc:
                if c not in deserialized_data['EAA']['seguro']:
                    return " Dados Inválidos "

            x = deserialized_data["EAA"]["seguranca"]["x"]
            y = deserialized_data["EAA"]["seguranca"]["y"]
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))

            assina = bytes.fromhex(
                deserialized_data["EAA"]["seguranca"]["assinatura"])

            deserialized_data["EAA"]["seguranca"]["assinatura"] = ""
            pub_key.verify(
                assina, cbor2.dumps(deserialized_data), ec.ECDSA(hashes.SHA256()))

            return str(deserialized_data)
    except:
        return " Dados Inválidos "

#  imprime os dados

print(test_document())

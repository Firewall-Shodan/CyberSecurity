import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Nossa estrutura de Dados

estrutura_dados = {
    "EAA": {
        "emissora": "",
        "data_emissao": "",
        "validade": "",

        "veiculo": {
            "marca": "",
            "modelo": "",
            "ano": "",
            "matricula": ""
        },

        "info_pessoal": {
            "nome": "",
            "data_nascimento": "",
            "endereco": "",
        },

        "seguranca": {
            "assinatura": "",
            "x": "",
            "y": ""
        },

        "seguro": {
            "numero_apolice": "",
            "seguradora": ""
        }
    }
}

# Carregar a Chave privada do ficheiro private_key.pem

with open("private_key.pem", "rb") as f:
    pem_priv_key = f.read()
    priv_key = serialization.load_pem_private_key(
        pem_priv_key,
        password=None,
    )

# Carregar a Chave publica do ficheiro public_key.pem

with open("public_key.pem", "rb") as f:
    pem_pub_key = f.read()
    pub_key = serialization.load_pem_public_key(
        pem_pub_key,
    )
    serialized_pub_key = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


#  impressão das Chaves

print(priv_key, pub_key)

#  Função create_document, recebe os dados do motorista como parâmetros de entrada e os retorna em formato CBOR

def create_document(emissora, data_emissao,
                    validade,
                    marca,
                    modelo,
                    ano,
                    matricula,
                    nome,
                    data_nascimento,
                    endereco,
                    numero_apolice,
                    seguradora):
    estrutura_dados['EAA']['emissora'] = emissora
    estrutura_dados['EAA']['data_emissao'] = data_emissao
    estrutura_dados['EAA']['validade'] = validade
    estrutura_dados['EAA']['veiculo']['marca'] = marca
    estrutura_dados['EAA']['veiculo']['modelo'] = modelo
    estrutura_dados['EAA']['veiculo']['ano'] = ano
    estrutura_dados['EAA']['veiculo']['matricula'] = matricula
    estrutura_dados['EAA']['info_pessoal']['nome'] = nome
    estrutura_dados['EAA']['info_pessoal']['data_nascimento'] = data_nascimento
    estrutura_dados['EAA']['info_pessoal']['endereco'] = endereco
    estrutura_dados['EAA']['seguro']['numero_apolice'] = numero_apolice
    estrutura_dados['EAA']['seguro']['seguradora'] = seguradora
    estrutura_dados['EAA']["seguranca"]["x"] = pub_key.public_numbers().x
    estrutura_dados['EAA']["seguranca"]["y"] = pub_key.public_numbers().y
    dados_cbor = cbor2.dumps(estrutura_dados)

    assinatura = priv_key.sign(dados_cbor, ec.ECDSA(hashes.SHA256()))

    estrutura_dados['EAA']["seguranca"]["assinatura"] = assinatura.hex()
    dados_cbor = cbor2.dumps(estrutura_dados)
    return dados_cbor

# Os parametros de entrada da funcão create_document

cbor_document = create_document("Uminho", "2022-01-08", "2022-12-31", "Toyota", "Camry", "2015", "LD-24-12-HT",
                                "José Miranda", "1980-01-01", "21 de Janeiro", "545435EGE", " Fidelidade")

# cria o arquivo document.cbor contendo os dados no formato Cbor

with open("document.cbor", "wb") as f:
    f.write(cbor_document)

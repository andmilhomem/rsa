import secrets
import math
import base64
import hashlib
import json
import random # Checar necessidade ao final

# Parâmetros:
TAM_HASH_BYTES = 32 # SHA-256
LABEL_HASH = b"" # Usada para gerar hash de início do pacote OAEP
TAM_P_Q_BITS = 1024 # O teto para n (e, portanto, para m) é o dobro desse valor
E_CANDIDATO = 65537

#Funções auxiliares:
def int_para_base64(i):
    return base64.b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big"))

def base64_para_int(b):
    return int.from_bytes(base64.b64decode(b),"big") 

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aplica_miller_rebin(n):
    #############
    #IMPLEMENTAR#
    #############
    # return True or False

    k=40
    # casos básicos
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # escreve n-1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # testes
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def aplica_mgf1(semente, tam_mascara):
    resultado = b""
    for cont in range(math.ceil(tam_mascara / TAM_HASH_BYTES)):
        cont_bytes = cont.to_bytes(4,"big")
        resultado += hashlib.sha3_256(semente + cont_bytes).digest()
    return resultado[:tam_mascara]

def gera_primo(qtde_bits):
    min_val = 1 << (qtde_bits - 1)
    max_val = (1 << qtde_bits ) - 1

    e_primo = False
    while not e_primo:
        candidato = secrets.randbelow(max_val - min_val + 1) + min_val # gera candidato no intervalo desejado   
        candidato = candidato | 1 # transforma em ímpar, se necessário
        e_primo = aplica_miller_rebin(candidato) # checa primalidade
    
    return candidato

def gera_e(phi_n):
    e = E_CANDIDATO
    while not math.gcd(e, phi_n) == 1:
        e += 2
    return e

# Funções principais:
def gera_chaves():
    p = gera_primo(TAM_P_Q_BITS)
    q = gera_primo(TAM_P_Q_BITS)
    n = p*q
    phi_n = (p-1)*(q-1)
    e = gera_e(phi_n)
    d = pow(e, -1, phi_n) # pow(a,b,c) = a^b mod c, ou seja, d = e^(-1) mod phi_n é o inverso modular de e
    return n, e, d

def cifra_decifra(base, expoente, n):
    return pow(base, expoente, n)

def empacota(m, n): # De acordo com OAEP
    # Calcula tamanho máximo da mensagem a partir de 'n'
    tam_n_em_bytes = (n.bit_length() + 7) // 8 
    tam_max_m_em_bytes = tam_n_em_bytes - 2 - (2 * TAM_HASH_BYTES) # -1 (0x00 na EM porque m < n), -1 (0x01 no DB como delimitador), -TAM_HASH_BYTES (hash do DB), -TAM_HASH_BYTES (masked_seed de EM)

    # Checa tamanho de 'm'
    tam_m = len(m)
    if tam_m > tam_max_m_em_bytes:
        return -1, f"O tamanho da mensagem ({tam_m} bytes) excedeu o limite máximo ({tam_max_m_em_bytes} bytes)!"
    
    # Gera padding de zeros
    tam_padding = tam_max_m_em_bytes - tam_m
    padding = b"\x00" * tam_padding

    # Gera hash do pacote
    h = hashlib.sha3_256(LABEL_HASH).digest()

    # Compõe pacote (gera data block)
    pacote = h + padding + b"\x01" + m

    # Mascara pacote (gera masked data block)
    semente = secrets.token_bytes(TAM_HASH_BYTES)
    mascara_pacote = aplica_mgf1(semente, len(pacote))
    pacote_mascarado = xor_bytes(pacote, mascara_pacote)

    # Mascara semente (gera masked seed)
    mascara_semente = aplica_mgf1(pacote_mascarado, TAM_HASH_BYTES)
    semente_mascarada = xor_bytes(semente, mascara_semente)

    # Compõe pacote final (gera encoded message) e converte para int
    pacote_final = int.from_bytes(b"\x00" + semente_mascarada + pacote_mascarado,"big") 
    return pacote_final, ""

def desempacota(pacote):
    # Decompõe pacote
    if pacote[0] != 0x00:
        return -1, "início diferente de 0x00"
    semente_mascarada = pacote[1: 1 + TAM_HASH_BYTES]
    pacote_mascarado = pacote[1 + TAM_HASH_BYTES:]

    # Desmascara semente
    mascara_semente = aplica_mgf1(pacote_mascarado, TAM_HASH_BYTES)
    semente_desmascarada = xor_bytes(semente_mascarada, mascara_semente)

    # Desmascara pacote
    mascara_pacote = aplica_mgf1(semente_desmascarada, len(pacote_mascarado))
    pacote_desmascarado = xor_bytes(pacote_mascarado, mascara_pacote)

    # Desempacota mensagem
    h = pacote_desmascarado[0:TAM_HASH_BYTES]
    resto = pacote_desmascarado[TAM_HASH_BYTES:]
    if h != hashlib.sha3_256(LABEL_HASH).digest(): # Checa hash
        return -1, "hash inválido"
    indice_separador = resto.find(b'\x01') # Checa separador
    if indice_separador == -1:
        return -1, "separador não localizado"
    padding = resto[:indice_separador]
    m_desempacotada = resto[indice_separador + 1:]
    for b in padding: # Checa padding
        if b != 0x00:
            return -1, "padding inválido"
    return 0, m_desempacotada

def assina_mensagem(m, n, d):
    # Gera e empacota hash
    h = hashlib.sha3_256(m).digest()
    h_empacotado, _ = empacota(h, n)

    # Cifra hash
    h_cifrado = cifra_decifra(h_empacotado, d, n)
    h_cifrado_base64 = int_para_base64(h_cifrado)

    # Compõe mensagem e assinatura
    m_assinada = json.dumps({
        "mensagem": m.decode("utf-8"),
        "assinatura": h_cifrado_base64.decode('utf-8')
    })
    
    # Converte mensagem para base64
    m_assinada_base64 = base64.b64encode(m_assinada.encode("utf-8"))

    return m_assinada_base64, h_cifrado_base64


while True:
    print("\n===========================")
    print("O que você deseja fazer?\n")
    print("1 - Gerar chaves públicas e privadas para A e B")
    print("2 - Cifrar mensagem de A para B")
    print("3 - Decifrar mensagem de A para B")
    print("4 - Assinar mensagem de A para B")
    print("5 - Verificar assinatura de mensagem de A para B")

    match input("\n> "):
        case "1": # Gera chaves
            n_A, e_A, d_A = gera_chaves()
            n_B, e_B, d_B = gera_chaves()

            print("========== CHAVES DE A ============")
            print(f"'n' (público): {int_para_base64(n_A).decode('utf-8')}")
            print(f"'e' (público): {int_para_base64(e_A).decode('utf-8')}")
            print(f"'d' (privado): {int_para_base64(d_A).decode('utf-8')}")
            print("========== CHAVES DE B ============")
            print(f"'n' (público): {int_para_base64(n_B).decode('utf-8')}")
            print(f"'e' (público): {int_para_base64(e_B).decode('utf-8')}")
            print(f"'d' (privado): {int_para_base64(d_B).decode('utf-8')}")
            print("===================================")

        case "2": # Cifra mensagem
            # Obtém 'n'
            print("Informe o componente 'n' da chave pública de B:") 
            n_B = base64_para_int(input("> ")) # Adicionar validação de input
            
            # Obtém 'e'
            print("Informe o componente 'e' da chave pública de B:")
            e_B = base64_para_int(input("> ")) # Adicionar validação de input

            # Obtém 'm'
            print(f"Informe a mensagem:")
            m = input("> ").encode("utf-8")

            # Empacota 'm'
            pacote, informacao = empacota(m, n_B)
            if pacote == -1:
                print(informacao)
                continue

            # Cifra pacote (RSA)
            c = cifra_decifra(pacote, e_B, n_B)
            print(f"Mensagem cifrada com sucesso:\n{int_para_base64(c).decode('utf-8')}")

        case "3": # Decifra mensagem
            # Obtém 'n'
            print("Informe o componente 'n' da chave privada de B:") 
            n_B = base64_para_int(input("> ")) # Adicionar validação de input
            
            # Obtém 'd'
            print("Informe o componente 'd' da chave privada de B:")
            d_B = base64_para_int(input("> ")) # Adicionar validação de input

            # Obtém mensagem cifrada
            print(f"Informe a mensagem cifrada:")
            c = base64_para_int(input("> "))

            # Decifra mensagem
            pacote_decifrado_int = cifra_decifra(c, d_B, n_B)
            tam_n_em_bytes = (n_B.bit_length() + 7) // 8 
            pacote_decifrado_bytes = pacote_decifrado_int.to_bytes(tam_n_em_bytes,"big")
            resultado, informacao = desempacota(pacote_decifrado_bytes)

            if resultado == -1:
                print(f"Mensagem corrompida ({informacao})!")
                continue
            
            print(f"Mensagem decifrada com sucesso:\n{informacao.decode("utf-8")}")

        case "4": # Assina mensagem
            # Obtém 'n'
            print("Informe o componente 'n' da chave privada de A:") 
            n_A = base64_para_int(input("> ")) # Adicionar validação de input
            
            # Obtém 'd'
            print("Informe o componente 'd' da chave privada de A:")
            d_A = base64_para_int(input("> ")) # Adicionar validação de input

            # Obtém 'm'
            print(f"Informe a mensagem:")
            m = input("> ").encode("utf-8")

            # Assina mensagem
            m_assinada_base64, assinatura_base64 = assina_mensagem(m, n_A, d_A)

            print(f"Mensagem assinada com sucesso: {m_assinada_base64.decode('utf-8')}")
            print(f"Assinatura: {assinatura_base64.decode('utf-8')}")

        case "5": # Verifica assinatura
            # Obtém 'n'
            print("Informe o componente 'n' da chave pública de A:") 
            n_A = base64_para_int(input("> ")) # Adicionar validação de input
            
            # Obtém 'e'
            print("Informe o componente 'e' da chave pública de A:")
            e_A = base64_para_int(input("> ")) # Adicionar validação de input

            # Obtém e decompõe a mensagem
            print(f"Informe a mensagem:")
            m_recebida = base64.b64decode(input("> ")).decode("utf-8")
            m_recebida_json = json.loads(m_recebida)
            m_recebida_bytes = m_recebida_json["mensagem"].encode("utf-8")
            a_recebida_base64 = m_recebida_json["assinatura"]
            
            # Decifra assinatura recebida
            a_recebida_int = base64_para_int(a_recebida_base64)
            a_decifrada_int = cifra_decifra(a_recebida_int, e_A, n_A)

            # Desempacota assinatura recebida
            tam_n_em_bytes = (n_A.bit_length() + 7) // 8
            a_decifrada_bytes = a_decifrada_int.to_bytes(tam_n_em_bytes,"big")
            resultado, informacao = desempacota(a_decifrada_bytes)

            if resultado == -1:
                print(f"Assinatura corrompida ({informacao})!")
                continue
            
            a_desempacotada_bytes = informacao

            # Verifica validade da assinatura
            h_bytes = hashlib.sha3_256(m_recebida_bytes).digest()
            if h_bytes == a_desempacotada_bytes:
                print("Integridade confirmada da seguinte mensagem:")
                print(m_recebida_bytes.decode("utf-8"))
            else:
                print("Assinatura inválida!")
        case _:
            "\n Opção inválida. Tente novamente.\n"




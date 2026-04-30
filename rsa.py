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

def formata_chave(n, e_ou_d, tipo):
    # Compõe JSON
    chave_formatada = ""
    if (tipo == "publ"):
        chave_formatada = json.dumps({
            "n": int_para_base64(n).decode('utf-8'),
            "e": int_para_base64(e_ou_d).decode('utf-8')
        })
    elif (tipo == "priv"):
        chave_formatada = json.dumps({
            "n": int_para_base64(n).decode('utf-8'),
            "d": int_para_base64(e_ou_d).decode('utf-8')
        })
    
    # Converte JSON para base64
    chave_formatada_base64 = base64.b64encode(chave_formatada.encode("utf-8"))

    return chave_formatada_base64.decode("utf-8")

def desformata_chave(chave):
    # Decompõe JSON
    chave_json = json.loads(base64.b64decode(chave).decode("utf-8"))
    n_base64 = chave_json.get("n")
    d_base64 = chave_json.get("d")
    e_base64 = chave_json.get("e")

    if d_base64 != None:
        return base64_para_int(n_base64), base64_para_int(d_base64)
    else:
        return base64_para_int(n_base64), base64_para_int(e_base64)

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

def empacota_oaep(m, n):
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

def desempacota_oaep(pacote):
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
    return 0, m_desempacotada.decode("utf-8")

def empacota_pss(m, n):
    # Calcula tamanho máximo da assinatura (encoded message) a partir de 'n'
    tam_max_a_bits = n.bit_length() - 1
    tam_max_a_bytes = (tam_max_a_bits + 7) // 8 

    # Checa se tamanho máximo da assinatura (encoded message) comporta os elementos obrigatórios (0x01 + salt no db; H + 0xbc na em)
    if tam_max_a_bytes < 2*TAM_HASH_BYTES + 2:
        return -1

    # Gera m_linha
    padding1 = b"\x00" * 8
    h = hashlib.sha3_256(m).digest() #mHash
    salt = secrets.token_bytes(32)
    m_linha = padding1 + h + salt

    # Gera padding de zeros do pacote
    tam_padding_pacote_bytes = tam_max_a_bytes - ( 2 * TAM_HASH_BYTES) - 2  # em menos (H + 0xbc) menos (0x01 + salt)
    padding_pacote = b"\x00" * tam_padding_pacote_bytes

    # Gera pacote (data block)
    pacote = padding_pacote + b"\x01" + salt

    # Gera hash final (H)
    h_final = hashlib.sha3_256(m_linha).digest()

    # Mascara pacote (gera masked data block)
    mascara_pacote = aplica_mgf1(h_final, len(pacote))
    pacote_mascarado = xor_bytes(pacote, mascara_pacote)

    # Zera os primeiros bits para garantir que 'em' não exceda 'n'
    bits_sobressalentes = (8 * tam_max_a_bytes) - tam_max_a_bits
    if bits_sobressalentes > 0:
        mascara =  (0xFF >> bits_sobressalentes)
        ba = bytearray(pacote_mascarado)
        ba[0] &= mascara
        pacote_mascarado_ajustado = bytes(ba)
    else:
        pacote_mascarado_ajustado = pacote_mascarado

    # Compõe pacote final (gera encoded message) e converte para int
    pacote_final = int.from_bytes(pacote_mascarado_ajustado + h_final + b"\xbc","big") 

    return pacote_final

def desempacota_pss(pacote, m, n):
    # Calcula tamanho máximo da assinatura (encoded message) a partir de 'n'
    tam_max_a_bits = n.bit_length() - 1
    tam_max_a_bytes = (tam_max_a_bits + 7) // 8 

    # Checa se os bits sobressalentes estão zerados
    bits_sobressalentes = (8 * tam_max_a_bytes) - tam_max_a_bits
    if bits_sobressalentes > 0:
        mascara = 0xFF << (8 - bits_sobressalentes) & 0xFF
        if (pacote[0] & mascara) != 0:
            return -1, "bits sobressalentes não zerados"

    # Decompõe pacote
    if pacote[-1] != 0xbc:
        return -1, "fim diferente de 0xbc"
    pos_h_final = len(pacote) - TAM_HASH_BYTES - 1
    pacote_mascarado = pacote[:pos_h_final]
    h_final_recebido = pacote[pos_h_final: pos_h_final + TAM_HASH_BYTES]

    # Desmascara pacote
    h = hashlib.sha3_256(m).digest()
    mascara_pacote = aplica_mgf1(h_final_recebido, len (pacote) - TAM_HASH_BYTES - 1)
    pacote_desmascarado = xor_bytes(pacote_mascarado, mascara_pacote)

    # Zera bits sobressalentes
    if bits_sobressalentes > 0:
        mascara = (0xFF >> bits_sobressalentes)
        ba = bytearray(pacote_desmascarado)
        ba[0] &= mascara
        pacote_desmascarado_ajustado = bytes(ba)
    else:
        pacote_desmascarado_ajustado = pacote_mascarado
    
    # Checa se padding está zerado
    tam_padding_pacote_bytes = tam_max_a_bytes - ( 2 * TAM_HASH_BYTES) - 2  # em menos (H + 0xbc) menos (0x01 + salt)
    padding = pacote_desmascarado_ajustado[:tam_padding_pacote_bytes]
    for b in padding: # Checa padding
        if b != 0x00:
            return -1, "padding inválido"
    
    # Checa se separador está correto
    if pacote_desmascarado_ajustado[tam_padding_pacote_bytes] != 1:
        return -1, "separador não localizado"
    
    # Calcula h_final
    salt = pacote_desmascarado_ajustado[tam_padding_pacote_bytes+1:]
    h = hashlib.sha3_256(m).digest() #mHash
    m_linha = b"\x00" * 8 + h + salt
    h_final = hashlib.sha3_256(m_linha).digest()

    # Verifica assinatura
    return 0, h_final_recebido == h_final

def assina_mensagem(m, n, d):
    # Gera e empacota assinatura
    a = empacota_pss(m, n)
    if a == -1: return a, "Erro ao assinar!"

    # Cifra assinatura
    a_cifrada = cifra_decifra(a, d, n)
    a_cifrada_base64 = int_para_base64(a_cifrada)

    # Compõe mensagem e assinatura
    m_assinada = json.dumps({
        "mensagem": m.decode("utf-8"),
        "assinatura": a_cifrada_base64.decode('utf-8')
    })
    
    # Converte mensagem para base64
    m_assinada_base64 = base64.b64encode(m_assinada.encode("utf-8"))

    return 0, m_assinada_base64.decode("utf-8")


while True:
    print("\n==================== OPÇÕES ====================\n")
    print("1 - Gerar chaves públicas e privadas para A e B")
    print("2 - Cifrar mensagem de A para B")
    print("3 - Decifrar mensagem de A para B")
    print("4 - Assinar mensagem de A para B")
    print("5 - Verificar assinatura de mensagem de A para B")
    print("\n================================================\n")

    try:
        match input("\n> "):
            case "1": # Gera chaves
                n_A, e_A, d_A = gera_chaves()
                n_B, e_B, d_B = gera_chaves()

                try:
                    chave_pública_A = formata_chave(n_A, e_A, "publ")
                    chave_privada_A = formata_chave(n_A, d_A, "priv")
                    chave_pública_B = formata_chave(n_B, e_B, "publ")
                    chave_privada_B = formata_chave(n_B, d_B, "priv")
                
                    print("\n========== CHAVE PÚBLICA DE A ============\n")
                    print(chave_pública_A)
                    print("\n========== CHAVE PRIVADA DE A ============\n")
                    print(chave_privada_A)
                    print("\n========== CHAVE PÚBLICA DE B ============\n")
                    print(chave_pública_B)
                    print("\n========== CHAVE PRIVADA DE B ============\n")
                    print(chave_privada_B)
                    print("\n==========================================\n")
                except:
                    print("Erro ao gerar chaves!")

            case "2": # Cifra mensagem
                # Obtém 'chave'
                print("Informe a chave pública de B:") 
                try:
                    n_B, e_B = desformata_chave(input("> "))
                except:
                    print("Erro ao processar chave!")
                    continue

                # Obtém 'm'
                print(f"Informe a mensagem:")
                m = input("> ").encode("utf-8")

                # Empacota 'm'
                pacote, informacao = empacota_oaep(m, n_B)
                if pacote == -1:
                    print(informacao)
                    continue

                # Cifra pacote (RSA)
                c = cifra_decifra(pacote, e_B, n_B)
                print(f"Mensagem cifrada com sucesso:\n{int_para_base64(c).decode('utf-8')}")

            case "3": # Decifra mensagem
                # Obtém 'chave'
                print("Informe a chave privada de B:") 
                try:
                    n_B, d_B = desformata_chave(input("> "))
                except:
                    print("Erro ao processar chave!")
                    continue

                # Obtém mensagem cifrada
                print(f"Informe a mensagem cifrada:")
                c = base64_para_int(input("> "))

                # Decifra mensagem
                pacote_decifrado_int = cifra_decifra(c, d_B, n_B)
                tam_n_em_bytes = (n_B.bit_length() + 7) // 8 
                pacote_decifrado_bytes = pacote_decifrado_int.to_bytes(tam_n_em_bytes,"big")
                resultado, informacao = desempacota_oaep(pacote_decifrado_bytes)

                if resultado == -1:
                    print(f"Mensagem corrompida ({informacao})!")
                    continue
                
                print(f"Mensagem decifrada com sucesso:\n{informacao}")

            case "4": # Assina mensagem
                # Obtém 'chave'
                print("Informe a chave privada de A:") 
                try:
                    n_A, d_A = desformata_chave(input("> "))
                except:
                    print("Erro ao processar chave!")
                    continue

                # Obtém 'm'
                print(f"Informe a mensagem:")
                m = input("> ").encode("utf-8")

                # Assina mensagem
                resultado, informacao = assina_mensagem(m, n_A, d_A)
                if resultado == -1: print(informacao)
                else: print(f"Mensagem assinada com sucesso:\n{informacao}")

            case "5": # Verifica assinatura
                # Obtém 'chave'
                print("Informe a chave pública de A:") 
                try:
                    n_A, e_A = desformata_chave(input("> "))
                except:
                    print("Erro ao processar chave!")
                    continue

                # Obtém e decompõe a mensagem
                print(f"Informe a mensagem (em base64):")
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
                resultado, informacao = desempacota_pss(a_decifrada_bytes, m_recebida_bytes, n_A)

                if resultado == -1:
                    print(f"Assinatura corrompida ({informacao})!")
                    continue
                if informacao == True:
                    print("Integridade confirmada da seguinte mensagem:")
                    print(m_recebida_bytes.decode("utf-8"))
                else:
                    print("Assinatura inválida!")

            case _:
                print("\n Opção inválida. Tente novamente.\n")
    except:
        exit()



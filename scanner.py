import socket
import ipaddress
import json
import time
from datetime import datetime


def alvo_permitido(ip):
    try:
        endereco = ipaddress.ip_address(ip)

        return endereco.is_private or endereco.is_loopback

    except ValueError:
        return False


def verificar_porta(ip, porta):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(0.3)

    resultado = sock.connect_ex((ip, porta))

    sock.close()

    return resultado == 0


def descobrir_servico(porta):
    try:
        return socket.getservbyport(porta, "tcp")

    except OSError:
        return "desconhecido"


def salvar_txt(ip, resultados, tempo_total):
    nome_arquivo = "resultado_scan.txt"

    with open(nome_arquivo, "w", encoding="utf-8") as arquivo:

        arquivo.write("SCAN DE PORTAS\n")
        arquivo.write("=" * 40 + "\n")

        arquivo.write(f"Alvo: {ip}\n")
        arquivo.write(f"Data: {datetime.now()}\n")
        arquivo.write(f"Tempo: {tempo_total:.2f} segundos\n\n")

        if resultados:

            for resultado in resultados:

                arquivo.write(
                    f"Porta {resultado['porta']} "
                    f"- {resultado['servico']} "
                    f"- ABERTA\n"
                )

        else:

            arquivo.write("Nenhuma porta aberta encontrada.\n")

    print(f"\n[+] Resultado salvo em {nome_arquivo}")


def salvar_json(ip, resultados, tempo_total):
    nome_arquivo = "resultado_scan.json"

    dados = {
        "alvo": ip,
        "data": str(datetime.now()),
        "tempo_segundos": round(tempo_total, 2),
        "quantidade_portas_abertas": len(resultados),
        "portas": resultados
    }

    with open(nome_arquivo, "w", encoding="utf-8") as arquivo:
        json.dump(
            dados,
            arquivo,
            indent=4,
            ensure_ascii=False
        )

    print(f"[+] Resultado salvo em {nome_arquivo}")


print("=" * 50)
print("           PYTHON PORT SCANNER")
print("=" * 50)

alvo = input("\nDigite o IP do laboratório: ")

try:
    ip = socket.gethostbyname(alvo)

except socket.gaierror:
    print("\n[ERRO] Endereço inválido.")
    exit()


if not alvo_permitido(ip):
    print("\n[ERRO] Apenas localhost ou redes privadas são permitidos.")
    exit()


try:

    porta_inicial = int(
        input("Digite a porta inicial: ")
    )

    porta_final = int(
        input("Digite a porta final: ")
    )

except ValueError:

    print("\n[ERRO] Digite apenas números.")
    exit()


if porta_inicial < 1 or porta_final > 65535:
    print("\n[ERRO] As portas devem estar entre 1 e 65535.")
    exit()


if porta_inicial > porta_final:
    print("\n[ERRO] A porta inicial deve ser menor que a final.")
    exit()


print("\n" + "=" * 50)

print(f"Alvo: {ip}")
print(f"Portas: {porta_inicial} até {porta_final}")

print("=" * 50)

print("\nIniciando scan...\n")


inicio = time.time()

resultados = []


for porta in range(porta_inicial, porta_final + 1):

    if verificar_porta(ip, porta):

        servico = descobrir_servico(porta)

        resultado = {
            "porta": porta,
            "servico": servico,
            "status": "aberta"
        }

        resultados.append(resultado)

        print(
            f"[ABERTA] "
            f"Porta {porta:<5} "
            f"Serviço: {servico}"
        )


fim = time.time()

tempo_total = fim - inicio


print("\n" + "=" * 50)

print("SCAN FINALIZADO")

print("=" * 50)

print(f"Tempo total: {tempo_total:.2f} segundos")

print(
    f"Portas abertas encontradas: "
    f"{len(resultados)}"
)


if not resultados:

    print("\nNenhuma porta aberta encontrada.")


salvar_txt(
    ip,
    resultados,
    tempo_total
)

salvar_json(
    ip,
    resultados,
    tempo_total
)
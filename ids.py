import socket
import struct
import time
import os

# Configurações
SYN_THRESHOLD = 5  # Limiar de pacotes SYN por segundo
BLOCK_DURATION = 60  # Tempo em segundos para manter o IP bloqueado
LOG_FILE = "syn_flood_log.txt"
blocked_ips = {}

# Função para adicionar IP na lista de bloqueio usando iptables
def block_ip(ip_address):
    os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
    blocked_ips[ip_address] = time.time()
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()} - IP bloqueado: {ip_address}\n")

# Função para limpar IPs desbloqueados após o tempo limite
def unblock_ips():
    current_time = time.time()
    for ip, block_time in list(blocked_ips.items()):
        if current_time - block_time > BLOCK_DURATION:
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            del blocked_ips[ip]
            with open(LOG_FILE, "a") as log:
                log.write(f"{time.ctime()} - IP desbloqueado: {ip}\n")

# Configurando o socket para capturar pacotes de rede
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Dicionário para armazenar contagem de pacotes SYN por IP
syn_counts = {}

print("Monitorando pacotes para detecção de SYN flood...")

while True:
    # Recebe o pacote
    packet, addr = sock.recvfrom(65565)
    
    # Extrai cabeçalho IP e cabeçalho TCP
    ip_header = packet[0:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    source_ip = socket.inet_ntoa(iph[8])

    # Extraindo cabeçalho TCP e flag SYN
    tcp_header = packet[20:40]
    tcph = struct.unpack("!HHLLBBHHH", tcp_header)
    flags = tcph[5]
    syn_flag = flags & 0x02  # Verifica se o flag SYN está definido

    if syn_flag:
        # Incrementa contagem de pacotes SYN para o IP de origem
        syn_counts[source_ip] = syn_counts.get(source_ip, 0) + 1

    # Verifica limiar de SYN flood e bloqueia IP
    current_time = time.time()
    for ip, count in list(syn_counts.items()):
        if count > SYN_THRESHOLD:
            print(f"Ataque SYN detectado de {ip}, bloqueando IP.")
            block_ip(ip)
            del syn_counts[ip]  # Remove do dicionário após bloqueio

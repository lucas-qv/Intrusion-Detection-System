# Simple Intrusion Detection System (IDS) for SYN Flood Detection

Este projeto é um sistema simples de detecção de intrusão (IDS) em Python, que monitora pacotes de rede para detectar ataques de SYN flood e bloqueia o IP de origem usando `iptables`.

## Descrição do Projeto

Este IDS captura pacotes de rede e conta a quantidade de pacotes SYN recebidos por segundo de cada IP. Se um IP enviar um número excessivo de pacotes SYN em um curto intervalo (indicando um possível ataque de SYN flood), o IDS adiciona o IP à lista de bloqueio usando `iptables`. Os IPs bloqueados são mantidos por um tempo determinado e depois desbloqueados automaticamente.

## Estrutura do Código

- **SYN_THRESHOLD**: Limiar de pacotes SYN por segundo para caracterizar um ataque.
- **BLOCK_DURATION**: Tempo em segundos pelo qual o IP permanecerá bloqueado.
- **LOG_FILE**: Nome do arquivo onde as atividades do IDS serão registradas.
- **blocked_ips**: Dicionário que armazena IPs bloqueados e o horário em que foram bloqueados.

### Funções Principais

1. **block_ip(ip_address)**: Bloqueia o IP utilizando `iptables` e registra o evento no arquivo de log.
2. **unblock_ips()**: Desbloqueia IPs após o período de bloqueio (especificado em `BLOCK_DURATION`).
3. **Socket de Captura de Pacotes**: Configura um socket raw para capturar pacotes TCP.

## Dependências

- **Python 3.x**
- Bibliotecas:
  - `socket`
  - `struct`
  - `time`
  - `os`
- **Acesso root**: Necessário para manipular `iptables` e capturar pacotes raw.

## Instruções de Uso

1. **Configuração do Ambiente**:
   - Certifique-se de que o Python 3.x está instalado.
   - Execute o script como root para ter permissão de manipular `iptables` e capturar pacotes.

2. **Execução**:
   - Execute o script IDS com permissões root:
     ```bash
     sudo python3 ids.py
     ```
   - Monitore o arquivo `syn_flood_log.txt` para verificar os logs de bloqueio e desbloqueio.

3. **Simulação de Ataque**:
   - Em outra máquina, simule um ataque SYN flood usando o comando:
     ```bash
     sudo nmap -Pn --max-rate 1000 -p- 192.168.X.X
     ```
   - Substitua `192.168.X.X` pelo IP do servidor monitorado.

## Arquivo de Log

O arquivo `syn_flood_log.txt` armazena informações sobre o bloqueio e desbloqueio de IPs, incluindo o horário do evento.

## Exemplo de Log

```plaintext
Mon Nov 01 16:43:12 2024 - IP bloqueado: 192.168.244.132
Mon Nov 01 16:44:12 2024 - IP desbloqueado: 192.168.244.132

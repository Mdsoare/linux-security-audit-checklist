# 🛡️ Linux Security Audit Checklist & One-Liners

![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Shell Script](https://img.shields.io/badge/shell-bash-blue.svg)
![Target](https://img.shields.io/badge/target-Linux%20Hardening-red.svg)

Uma coleção de comandos rápidos e *one-liners* em Shell Script voltados para a **auditoria de segurança, verificação de hardening e identificação de vetores de elevação de privilégios** em servidores Linux.

---

## ⚠️ Isenção de Responsabilidade (Disclaimer)

> Este projeto destina-se **exclusivamente a fins educacionais, auditorias de segurança autorizadas e tarefas de hardening de infraestrutura**. O uso destas ferramentas contra alvos sem autorização prévia e expressa é estritamente proibido. Os mantenedores não se responsabilizam por eventuais danos causados por uso indevido.

---

## 📌 Como Utilizar

Você pode executar os comandos individualmente no terminal conforme a necessidade ou copiar a **Suite Executiva** ao final para uma triagem rápida.

> ⚠️ **Nota:** Alguns comandos requerem privilégios de `root` ou `sudo` para ler arquivos restritos (como `/etc/shadow`) ou inspecionar parâmetros em memória do daemon `sshd`.

---

## 🚀 Checklist de Auditoria

1. [Contexto e Identificação do Host](#1-contexto-e-identificação-do-host)
2. [Usuários, Privilégios e Autenticação](#2-usuários-privilégios-e-autenticação)
3. [Auditoria Avançada de SSH (Hardening Baseline)](#3-auditoria-avançada-de-ssh-hardening-baseline)
4. [Permissões de Arquivos e Binários Críticos](#4-permissões-de-arquivos-e-binários-críticos)
5. [Conexões de Rede e Processos Ativos](#5-conexões-de-rede-e-processos-ativos)
6. [Persistência e Agendamento de Tarefas](#6-persistência-e-agendamento-de-tarefas)
7. [⚡ Suite Executável (One-Liner Consolidado)](#-suite-executável-one-liner-consolidado)

---

## 💻 Comandos por Categoria

### 1. Contexto e Identificação do Host
Coleta as informações básicas da máquina e do primeiro IP de rede ativo.

```bash
echo "--- [CHECK] Host & Context ---"
echo "Host: $(hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A')"
```
---
### 2. Usuários, Privilégios e Autenticação
Verifica usuários com UID 0 (acesso root direto), contas sem senha e permissões do sudoers.

```Bash
echo "--- [CHECK] Root Privileges (UID 0) ---"
getent passwd | awk -F: '$3 == 0 && $1 != "root" {print "!!! ALERTA: Usuário não-root com UID 0: " $1}'

echo "--- [CHECK] Passwordless Accounts ---"
sudo awk -F: '($2 == "") { print "!!! ALERTA: " $1 " sem senha configurada!" }' /etc/shadow 2>/dev/null

echo "--- [CHECK] Shells Interativos ---"
getent passwd | grep -E '/(ba|z|k|c)?sh$' | awk -F: '{printf "Usuário: %-15s Shell: %s\n", $1, $7}'

echo "--- [CHECK] Sudoers (NOPASSWD) ---"
sudo grep -rI "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "OK: Nenhuma regra NOPASSWD explícita encontrada."
```
---
### 3. Auditoria Avançada de SSH (Hardening Baseline)
O comando `sshd -T` lê as configurações efetivas e ativas em memória do serviço SSH (resolvendo `Includes`, diretivas implícitas e blocos `Match`).

```Bash
echo "--- [CHECK] SSH Hardening Audit ---"
sudo sshd -T 2>/dev/null | awk '
  /permitrootlogin/        { printf "Root Login:          %-20s (Ideal: no / prohibit-password)\n", $2 }
  /passwordauthentication/ { printf "Password Auth:       %-20s (Ideal: no)\n", $2 }
  /pubkeyauthentication/   { printf "PubKey Auth:         %-20s (Ideal: yes)\n", $2 }
  /permitemptypasswords/   { printf "Empty Passwords:     %-20s (Ideal: no)\n", $2 }
  /maxauthtries/           { printf "Max Auth Tries:      %-20s (Ideal: <= 4)\n", $2 }
  /clientaliveinterval/    { printf "Alive Interval (s):  %-20s (Ideal: > 0, ex: 300)\n", $2 }
  /allowtcpforwarding/     { printf "TCP Forwarding:      %-20s (Ideal: no, exceto bastiões)\n", $2 }
  /x11forwarding/          { printf "X11 Forwarding:      %-20s (Ideal: no)\n", $2 }
'
```

#### 🔑 Chaves SSH Autorizadas
Mapeia os usuários do sistema e verifica a existência de chaves públicas em `~/.ssh/authorized_keys`:

```Bash
echo "--- [CHECK] SSH Authorized Keys ---"
getent passwd | awk -F: '$3 >= 1000 || $3 == 0 {print $1 ":" $6}' | while IFS=: read -r user home; do
  auth_file="$home/.ssh/authorized_keys"
  [ -f "$auth_file" ] && {
    count=$(wc -l < "$auth_file")
    echo "Usuário: $user ($count chave(s))"
    awk '{if ($3 != "") print "  - " $3; else print "  - [Sem Comentário/Nome]";}' "$auth_file"
  }
done
```
---
### 4. Permissões de Arquivos e Binários Críticos
Mapeia arquivos editáveis no `/etc` e busca binários com bit SUID configurado que podem ser explorados para Privilege Escalation (GTFOBins).

```Bash
echo "--- [CHECK] SUID Binaries (GTFOBins) ---"
find / -perm -4000 -type f 2>/dev/null | grep -E '/(whoami|cp|mv|vim|nano|find|awk|python|python3|perl|sh|bash|pkexec|nmap|env|capsh|gdb)$'

echo "--- [CHECK] World-Writable Configs em /etc ---"
find /etc -type f -perm -o+w 2>/dev/null
```

---
### 5. Conexões de Rede e Processos Ativos
Lista sessões interativas ativas e portas TCP/UDP abertas aguardando conexões (`LISTEN`).

```Bash
echo "--- [CHECK] Active Sessions & Open Ports ---"
w -h
echo "--- Portas em Escuta ---"
sudo ss -tulpn | grep LISTEN
```

---
### 6. Persistência e Agendamento de Tarefas
Identifica rotinas automáticas no cron e timers gerenciados pelo systemd.

```Bash
echo "--- [CHECK] Cron Jobs (Sistema e Usuários) ---"
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null

echo "--- [CHECK] Systemd Timers Ativos ---"
systemctl list-timers --all --no-pager 2>/dev/null | head -n 15
```
---
## ⚡ Suite Executável (One-Liner Consolidado)
Execute todas as verificações acima em um único comando formatado no terminal:

```Bash
echo "=== INICIANDO AUDITORIA DE SEGURANÇA LINUX ==="; \
echo -e "\n--- [CHECK] Host & Context ---"; echo "Host: $(hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A')"; \
echo -e "\n--- [CHECK] Root Privileges (UID 0) ---"; getent passwd | awk -F: '$3 == 0 && $1 != "root" {print "!!! ALERTA: Usuário não-root com UID 0: " $1}'; \
echo -e "\n--- [CHECK] Passwordless Accounts ---"; sudo awk -F: '($2 == "") { print "!!! ALERTA: " $1 " sem senha!" }' /etc/shadow 2>/dev/null; \
echo -e "\n--- [CHECK] Shells Interativos ---"; getent passwd | grep -E '/(ba|z|k|c)?sh$' | awk -F: '{printf "Usuário: %-15s Shell: %s\n", $1, $7}'; \
echo -e "\n--- [CHECK] Sudoers (NOPASSWD) ---"; sudo grep -rI "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "OK: Sem permissões NOPASSWD óbvias"; \
echo -e "\n--- [CHECK] SSH Hardening Audit ---"; sudo sshd -T 2>/dev/null | awk '/permitrootlogin/{printf "Root Login: %-15s\n",$2} /passwordauthentication/{printf "Password Auth: %-15s\n",$2} /pubkeyauthentication/{printf "PubKey Auth: %-15s\n",$2} /permitemptypasswords/{printf "Empty Passwords: %-15s\n",$2} /maxauthtries/{printf "Max Auth Tries: %-15s\n",$2} /clientaliveinterval/{printf "Alive Interval: %-15s\n",$2} /allowtcpforwarding/{printf "TCP Forwarding: %-15s\n",$2}'; \
echo -e "\n--- [CHECK] SSH Authorized Keys ---"; getent passwd | awk -F: '$3 >= 1000 || $3 == 0 {print $1 ":" $6}' | while IFS=: read -r user home; do auth_file="$home/.ssh/authorized_keys"; [ -f "$auth_file" ] && { count=$(wc -l < "$auth_file"); echo "Usuário $user ($count chave(s)):"; awk '{if ($3 != "") print "  - " $3; else print "  - [Sem Comentário]";}' "$auth_file"; }; done; \
echo -e "\n--- [CHECK] SUID Binaries (GTFOBins) ---"; find / -perm -4000 -type f 2>/dev/null | grep -E '/(whoami|cp|mv|vim|nano|find|awk|python|python3|perl|sh|bash|pkexec|nmap|env|capsh|gdb)$'; \
echo -e "\n--- [CHECK] World-Writable Configs (/etc) ---"; find /etc -type f -perm -o+w 2>/dev/null; \
echo -e "\n--- [CHECK] Active Sessions & Open Ports ---"; w -h; sudo ss -tulpn | grep LISTEN; \
echo -e "\n--- [CHECK] Cron Jobs & Timers ---"; ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null; \
echo -e "\n=== AUDITORIA CONCLUÍDA ==="
```

---
## 📜 Licença
Este projeto está licenciado sob a Licença MIT. Sinta-se à vontade para utilizar, alterar e integrar às suas rotinas de hardening e auditoria de infraestrutura.
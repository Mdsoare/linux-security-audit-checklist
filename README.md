# 🛡️ Linux Security Audit Checklist & One-Liners

![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Target Linux Hardening](https://img.shields.io/badge/target-Linux%20Hardening-red.svg)
[![Docs Quality & Security](https://github.com/Mdsoare/linux-security-audit-checklist/actions/workflows/sec-scan.yml/badge.svg)](https://github.com/Mdsoare/linux-security-audit-checklist/actions/workflows/sec-scan.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

---

Uma coleção de comandos rápidos e *one-liners* em Shell Script voltados para a **auditoria forense de segurança, verificação de hardening e identificação de vetores de elevação de privilégios (PrivEsc)** em servidores Linux.

Projetado para auditores, administradores de sistemas, analistas de SOC e consultores de Red/Blue Team que necessitam de triagem precisa.

---

## ⚠️ Isenção de Responsabilidade (Disclaimer) e Conformidade (LGPD/GDPR)

> Este projeto destina-se **exclusivamente a fins educacionais, auditorias de segurança autorizadas e tarefas de hardening de infraestrutura**. O uso destas ferramentas contra alvos sem autorização prévia e expressa é estritamente proibido. Os mantenedores não se responsabilizam por eventuais danos causados por uso indevido.
>
> 🔒 **Privacidade de Dados:** A coleta de dados deste script limita-se a configurações de sistema e metadados de contas. Nenhum dado pessoal sensível é extraído ou transmitido.

---

## 📌 Como Utilizar

Você pode executar os comandos individualmente no terminal conforme a necessidade técnica ou copiar a **Suite Executiva** ao final para uma triagem rápida no host.

> ⚠️ **Nota de Elevação:** Vários comandos exigem privilégios de `root` ou permissões via `sudo` para consultar a base de hashes (`getent shadow`), inspecionar parâmetros ativos do daemon `sshd` ou ler crontabs de outros usuários.

---

## 🚀 Checklist de Auditoria

1. [Contexto do Host e Sistema](#1-contexto-do-host-e-sistema)
2. [Usuários, Privilégios e Autenticação](#2-usuários-privilégios-e-autenticação)
3. [Auditoria Avançada de SSH (Hardening Baseline)](#3-auditoria-avançada-de-ssh-hardening-baseline)
4. [Persistência via Chaves SSH Autorizadas](#4-persistência-via-chaves-ssh-autorizadas)
5. [Permissões de Arquivos e Binários Críticos (GTFOBins)](#5-permissões-de-arquivos-e-binários-críticos-gtfobins)
6. [Conexões de Rede e Processos em Escuta](#6-conexões-de-rede-e-processos-em-escuta)
7. [Persistência e Agendamento de Tarefas (Cron & Timers)](#7-persistência-e-agendamento-de-tarefas-cron--timers)
8. [Suite Executiva (One-Liner)](#-suite-executiva-one-liner)

---

## 💻 Comandos por Categoria

### 1. Contexto do Host e Sistema
Coleta informações essenciais do ambiente (Hostname, IP principal e versão do Kernel/Sistema).

```bash
echo "--- [CHECK] Host & Context ---"
echo "Host: $(hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A') | Kernel: $(uname -r)"
```

---

### 2. Usuários, Privilégios e Autenticação
Identifica usuários não-root com UID 0, contas sem senha configurada, regras explícitas no `sudoers` sem senha e mapeia shells válidos de forma dinâmica.

```bash
echo "--- [CHECK] Root Privileges (UID 0 Adicionais) ---"
getent passwd | awk -F: '$3 == 0 && $1 != "root" {print "!!! ALERTA: Usuário não-root com UID 0: " $1}'

echo "--- [CHECK] Passwordless Accounts ---"
sudo getent shadow | awk -F: '($2 == "" || $2 == "!") { print "!!! ALERTA: Conta sem senha ou desbloqueada sem hash: " $1 }'

echo "--- [CHECK] Shells Interativos Efetivos (/etc/shells) ---"
getent passwd | awk -F: 'NR==FNR{shells[$1]; next} $7 in shells {printf "Usuário: %-15s Shell: %s\n", $1, $7}' /etc/shells -

echo "--- [CHECK] Sudoers (NOPASSWD sem comentários) ---"
sudo grep -Erv '^[[:space:]]*#' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -i "NOPASSWD" || echo "OK: Nenhuma regra NOPASSWD explícita encontrada."
```

---

### 3. Auditoria Avançada de SSH (Hardening Baseline)
Consulta a configuração em memória do daemon `sshd` (`sshd -T`), garantindo a validação real das diretivas ativas (resolvendo arquivos incluídos e blocos `Match`).

```bash
echo "--- [CHECK] SSH Hardening Audit ---"
sudo sshd -T 2>/dev/null | awk '
  /permitrootlogin/        { printf "Root Login:           %-20s (Ideal: no / prohibit-password)\n", $2 }
  /passwordauthentication/ { printf "Password Auth:        %-20s (Ideal: no)\n", $2 }
  /pubkeyauthentication/   { printf "PubKey Auth:          %-20s (Ideal: yes)\n", $2 }
  /permitemptypasswords/   { printf "Empty Passwords:      %-20s (Ideal: no)\n", $2 }
  /maxauthtries/           { printf "Max Auth Tries:       %-20s (Ideal: <= 4)\n", $2 }
  /clientaliveinterval/    { printf "Alive Interval (s):   %-20s (Ideal: > 0, ex: 300)\n", $2 }
  /allowtcpforwarding/     { printf "TCP Forwarding:       %-20s (Ideal: no)\n", $2 }
  /x11forwarding/          { printf "X11 Forwarding:       %-20s (Ideal: no)\n", $2 }
'
```

---

### 4. Persistência via Chaves SSH Autorizadas
🔑 Mapeia chaves públicas em `~/.ssh/authorized_keys`, desconsiderando linhas de comentários e identificando comentários das chaves ativas (`ssh-rsa`, `ed25519`, `ecdsa`).

```bash
echo "--- [CHECK] SSH Persistence (Authorized Keys) ---"
getent passwd | awk -F: '$3 >= 1000 || $3 == 0 {print $1 ":" $6}' | while IFS=: read -r user home; do
  auth_file="$home/.ssh/authorized_keys"
  [ -f "$auth_file" ] && {
    count=$(grep -cE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)' "$auth_file")
    echo "Usuário $user ($count chave(s) ativa(s)):"
    grep -E '^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)' "$auth_file" | awk '{if ($NF ~ /@/) print "  - Comment: " $NF; else print "  - Key: " substr($2,1,15) "... [Sem comentário]";}'
  }
done
```

---

### 5. Permissões de Arquivos e Binários Críticos (GTFOBins)
Busca binários com permissão SUID (`-perm -4000`) conhecidos no repositório **GTFOBins** que permitem bypassing de privilégios localmente. Utiliza a opção `-xdev` para evitar travamentos em sistemas de arquivos remotos (NFS/CIFS).

```bash
echo "--- [CHECK] SUID Binaries (GTFOBins Risk) ---"
find / -xdev -perm -4000 -type f 2>/dev/null | grep -E '/(whoami|cp|mv|vim|nano|find|awk|python[0-9.]*|perl|sh|bash|env|capsh|nmap|flock|pkexec|gdb|systemctl|nice|taskset|ionice)$'

echo "--- [CHECK] World-Writable Configs (/etc) ---"
find /etc -type f -perm -o+w 2>/dev/null
```

---

### 6. Conexões de Rede e Processos em Escuta
Mapeia sessões interativas no sistema e exibe sockets TCP/UDP aguardando conexões (`LISTEN`) juntamente com seus PIDs e nomes de processos.

```bash
echo "--- [CHECK] Active Sessions & Open Ports ---"
w -h
echo "--- Portas em Escuta ---"
sudo ss -tulpn | grep LISTEN
```

---

### 7. Persistência e Agendamento de Tarefas (Cron & Timers)
Verifica tarefas agendadas em nível individual por usuário (via `crontab`), diretórios do cron global e timers gerenciados pelo `systemd`.

```bash
echo "--- [CHECK] User Crontabs ---"
for u in $(getent passwd | awk -F: '$3>=1000 || $3==0 {print $1}'); do
  crons=$(sudo crontab -u "$u" -l 2>/dev/null | grep -v '^[[:space:]]*#')
  if [ -n "$crons" ]; then
    echo "=== Cron: $u ==="
    echo "$crons"
  fi
done

echo "--- [CHECK] Systemd Timers Ativos ---"
systemctl list-timers --all --no-pager 2>/dev/null | head -n 12
```

---

## ⚡ Suite Executiva (One-Liner)
Execute todo o checklist acima formatado em uma única linha de execução no terminal:

```bash
echo "=== INICIANDO AUDITORIA DE SEGURANÇA LINUX ==="; \
echo -e "\n--- [CHECK] Host & Context ---"; echo "Host: $(hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A') | Kernel: $(uname -r)"; \
echo -e "\n--- [CHECK] Root Privileges (UID 0) ---"; getent passwd | awk -F: '$3 == 0 && $1 != "root" {print "!!! ALERTA: Usuário não-root com UID 0: " $1}'; \
echo -e "\n--- [CHECK] Passwordless Accounts ---"; sudo getent shadow | awk -F: '($2 == "" || $2 == "!") { print "!!! ALERTA: Conta sem senha ou desbloqueada: " $1 }'; \
echo -e "\n--- [CHECK] Shells Interativos (/etc/shells) ---"; getent passwd | awk -F: 'NR==FNR{shells[$1]; next} $7 in shells {printf "Usuário: %-15s Shell: %s\n", $1, $7}' /etc/shells -; \
echo -e "\n--- [CHECK] Sudoers (NOPASSWD) ---"; sudo grep -Erv '^[[:space:]]*#' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -i "NOPASSWD" || echo "OK: Sem permissões NOPASSWD explícitas"; \
echo -e "\n--- [CHECK] SSH Hardening Audit ---"; sudo sshd -T 2>/dev/null | awk '/permitrootlogin/{printf "Root Login: %-15s\n",$2} /passwordauthentication/{printf "Password Auth: %-15s\n",$2} /pubkeyauthentication/{printf "PubKey Auth: %-15s\n",$2} /permitemptypasswords/{printf "Empty Passwords: %-15s\n",$2} /maxauthtries/{printf "Max Auth Tries: %-15s\n",$2} /clientaliveinterval/{printf "Alive Interval: %-15s\n",$2} /allowtcpforwarding/{printf "TCP Forwarding: %-15s\n",$2}'; \
echo -e "\n--- [CHECK] SSH Authorized Keys ---"; getent passwd | awk -F: '$3 >= 1000 || $3 == 0 {print $1 ":" $6}' | while IFS=: read -r user home; do auth_file="$home/.ssh/authorized_keys"; [ -f "$auth_file" ] && { count=$(grep -cE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)' "$auth_file"); echo "Usuário $user ($count chave(s) ativa(s)):"; grep -E '^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)' "$auth_file" | awk '{if ($NF ~ /@/) print "  - Comment: " $NF; else print "  - Key: " substr($2,1,15) "...";}'; }; done; \
echo -e "\n--- [CHECK] SUID Binaries (GTFOBins) ---"; find / -xdev -perm -4000 -type f 2>/dev/null | grep -E '/(whoami|cp|mv|vim|nano|find|awk|python[0-9.]*|perl|sh|bash|env|capsh|nmap|flock|pkexec|gdb|systemctl|nice|taskset|ionice)$'; \
echo -e "\n--- [CHECK] World-Writable Configs (/etc) ---"; find /etc -type f -perm -o+w 2>/dev/null; \
echo -e "\n--- [CHECK] Active Sessions & Open Ports ---"; w -h; sudo ss -tulpn | grep LISTEN; \
echo -e "\n--- [CHECK] User Crontabs ---"; for u in $(getent passwd | awk -F: '$3>=1000 || $3==0 {print $1}'); do crons=$(sudo crontab -u "$u" -l 2>/dev/null | grep -v '^[[:space:]]*#'); if [ -n "$crons" ]; then echo "=== Cron: $u ==="; echo "$crons"; fi; done; \
echo -e "\n=== AUDITORIA CONCLUÍDA ==="
```

---

## 📜 Licença
Este projeto está licenciado sob a Licença MIT. Sinta-se à vontade para utilizar, alterar e integrar às suas rotinas de hardening e auditoria de infraestrutura.

---

*Desenvolvido por **Marcelo Soares** | Especialista em Segurança da Informação e Computação Forense.*
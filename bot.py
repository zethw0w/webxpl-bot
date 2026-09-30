"""
bot.py — Web XPL Bot (Telegram)

Bot de reconhecimento ativo/passivo para pentests web autorizados.
Comandos: /nmap /gau /crt /ipinfo /whois /webxpl /sqli.

Uso:
    1. Crie um bot com o @BotFather e copie o token.
    2. Coloque o token em .env  ->  TELEGRAM_TOKEN=...
    3. python bot.py
"""

import asyncio
import html
import logging
import os

from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

import recon

# --- Setup ------------------------------------------------------------------

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("webxpl-bot")
# Silencia os logs HTTP do httpx (evita poluir a saída E expor o token nas URLs).
logging.getLogger("httpx").setLevel(logging.WARNING)

TG_MAX = 3500  # margem segura abaixo do limite de 4096 chars do Telegram


# --- Helpers de envio -------------------------------------------------------

def _chunk(text: str, size: int = TG_MAX) -> list[str]:
    """Fatia `text` em pedaços <= size, preferindo quebrar em linhas."""
    pedacos, atual = [], ""
    for linha in text.splitlines(keepends=True):
        # linha isolada maior que o limite: fatia na força bruta
        while len(linha) > size:
            if atual:
                pedacos.append(atual)
                atual = ""
            pedacos.append(linha[:size])
            linha = linha[size:]
        if len(atual) + len(linha) > size:
            pedacos.append(atual)
            atual = ""
        atual += linha
    if atual:
        pedacos.append(atual)
    return pedacos or ["(vazio)"]


async def responder_saida(update: Update, titulo: str, corpo: str) -> None:
    """Envia `corpo` dentro de blocos <pre>, fatiado e com HTML escapado."""
    for i, pedaco in enumerate(_chunk(corpo)):
        prefixo = f"<b>{html.escape(titulo)}</b>\n" if i == 0 else ""
        await update.message.reply_text(
            f"{prefixo}<pre>{html.escape(pedaco)}</pre>",
            parse_mode=ParseMode.HTML,
        )


async def _executar(update, context, titulo, func, arg_desc, exemplo):
    """
    Fluxo comum a todos os comandos:
    valida argumento -> mostra 'digitando' -> roda função em thread -> responde.
    """
    if not context.args:
        await update.message.reply_text(
            f"⚠️ Uso: informe {arg_desc}.\nExemplo: {exemplo}"
        )
        return

    alvo = context.args[0]
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        # funções de recon são bloqueantes -> rodam fora do event loop
        resultado = await asyncio.to_thread(func, alvo)
        await responder_saida(update, f"{titulo}: {alvo}", resultado)
    except recon.ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
    except Exception as exc:  # rede/ferramenta inesperada
        logger.exception("Erro em %s", titulo)
        await update.message.reply_text(f"❌ Erro inesperado: {exc}")


# --- Handlers ---------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🤖 *Web XPL Bot* — recon para pentests web autorizados.\n\n"
        "Comandos:\n"
        "• `/nmap <host>` — scan de portas/serviços\n"
        "• `/gau <domínio>` — URLs conhecidas (passivo)\n"
        "• `/crt <domínio>` — subdomínios via crt.sh\n"
        "• `/ipinfo <IP>` — geolocalização/ASN do IP\n"
        "• `/whois <domínio>` — dados de registro (bônus)\n"
        "• `/webxpl` — resolve o desafio FIAP WEB XPL (bônus CTF)\n"
        "• `/sqli` — explora SQL Injection na vAPI local (bônus CTF)\n\n"
        "⚠️ Use apenas contra alvos que você tem autorização para testar.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await cmd_start(update, context)


async def cmd_nmap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _executar(update, context, "nmap", recon.run_nmap,
                    "um host (domínio ou IP)", "/nmap scanme.nmap.org")


async def cmd_gau(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _executar(update, context, "gau", recon.run_gau,
                    "um domínio", "/gau exemplo.com")


async def cmd_crt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _executar(update, context, "crt.sh", recon.run_crt,
                    "um domínio", "/crt exemplo.com")


async def cmd_ipinfo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _executar(update, context, "ipinfo", recon.run_ipinfo,
                    "um IP", "/ipinfo 8.8.8.8")


async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _executar(update, context, "whois", recon.run_whois,
                    "um domínio", "/whois exemplo.com")


async def cmd_webxpl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """(Bônus CTF) Resolve o desafio FIAP WEB XPL (type juggling + cookie forjado)."""
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        resultado = await asyncio.to_thread(recon.solve_webxpl)
        await responder_saida(update, "Web XPL — desafio resolvido", resultado)
    except recon.ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
    except Exception as exc:
        logger.exception("Erro em webxpl")
        await update.message.reply_text(f"❌ Erro inesperado: {exc}")


async def cmd_sqli(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """(Bônus CTF) Explora SQL Injection UNION-based na vAPI local (POST /vapi/api8/user/login)."""
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        resultado = await asyncio.to_thread(recon.solve_sqli)
        await responder_saida(update, "SQL Injection — vAPI api8/user/login", resultado)
    except recon.ReconError as exc:
        await update.message.reply_text(f"❌ {exc}")
    except Exception as exc:
        logger.exception("Erro em sqli")
        await update.message.reply_text(f"❌ Erro inesperado: {exc}")


# --- Main -------------------------------------------------------------------

def main() -> None:
    # Python 3.12+/3.14: garante um event loop atual (PTB 21.x usa asyncio.get_event_loop(),
    # que nas versões novas do Python não cria mais um loop sozinho).
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    if not TOKEN:
        raise SystemExit(
            "TELEGRAM_TOKEN ausente. Copie .env.example para .env e coloque o token do BotFather."
        )

    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("nmap", cmd_nmap))
    app.add_handler(CommandHandler("gau", cmd_gau))
    app.add_handler(CommandHandler("crt", cmd_crt))
    app.add_handler(CommandHandler("ipinfo", cmd_ipinfo))
    app.add_handler(CommandHandler("whois", cmd_whois))
    app.add_handler(CommandHandler("webxpl", cmd_webxpl))
    app.add_handler(CommandHandler("sqli", cmd_sqli))

    logger.info("Web XPL Bot iniciado. Aguardando comandos...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

import os
import time
import json
import requests
from typing import Any
from web3 import Web3
from dotenv import load_dotenv

# === Load environment variables from .env ===
load_dotenv()

# === Configuration ===
RPC_URL       = os.getenv("RPC_URL", "https://evmrpc-testnet.0g.ai")
BOT_TOKEN     = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID       = os.getenv("TELEGRAM_CHAT_ID")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))

# === Monitored addresses ===
# FROM_ADDR = the sender address you want to monitor (e.g., your wallet or any wallet)
FROM_ADDR = Web3.to_checksum_address("sender_address")
# TO_ADDR   = the destination address to monitor (your wallet OR a smart contract)
TO_ADDR   = Web3.to_checksum_address("0x3A0d1d67497Ad770d6f72e7f4B8F0BAbaa2A649C")

# State file to avoid duplicate notifications across runs
STATE_FILE = "watch_0g_state.json"

# === Helpers ===
MDV2_SPECIAL = r"_*[]()~`>#+-=|{}.!\\"

def escape_md(text: str) -> str:
    """Escape special characters for Telegram MarkdownV2."""
    return "".join("\\" + c if c in MDV2_SPECIAL else c for c in str(text))

def short_addr(addr: str) -> str:
    """Shorten an address like 0xABCD...1234 for readability."""
    s = str(addr)
    return s[:6] + "..." + s[-4:] if len(s) > 10 else s

def fmt_num(val, decimals=6):
    """Format numeric values with fixed decimals; fall back to raw string."""
    try:
        return f"{float(val):.{decimals}f}"
    except Exception:
        return str(val)

def method_selector(tx_input: Any) -> str:
    """
    Return the 4-byte method selector as hex string, e.g. '0xef3e12dc'.
    Works whether tx_input is bytes, HexBytes, or '0x...' string.
    """
    if tx_input in (None, b"", "0x", "0x0"):
        return "0x"
    try:
        # If bytes-like: take first 4 bytes
        if isinstance(tx_input, (bytes, bytearray)):
            return "0x" + tx_input[:4].hex()
        # If HexBytes
        try:
            from hexbytes import HexBytes
            if isinstance(tx_input, HexBytes):
                return "0x" + bytes(tx_input)[:4].hex()
        except Exception:
            pass
        # If string '0x...': first 10 chars = '0x' + 8 hex chars
        s = str(tx_input)
        if s.startswith("0x"):
            return s[:10] if len(s) >= 10 else s
        # Fallback
        return "0x" + bytes(s, "latin1")[:4].hex()
    except Exception:
        return "0x"

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"last_block": None, "seen": []}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def send_tg(text: str):
    """Send a Telegram message using MarkdownV2 formatting."""
    if not BOT_TOKEN or not CHAT_ID:
        print("⚠️  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    r = requests.post(
        url,
        data={
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True,
        },
        timeout=20,
    )
    if not r.ok:
        print("Failed to send Telegram message:", r.text)

def fmt_time_utc(ts: int) -> str:
    """Format Unix timestamp into UTC string."""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

# === Main ===
def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise RuntimeError("Failed to connect to RPC")

    state = load_state()
    if state["last_block"] is None:
        state["last_block"] = w3.eth.block_number

    print(f"✅ Connected. Monitoring from block {state['last_block']} (interval {POLL_INTERVAL}s)")

    while True:
        try:
            head = w3.eth.block_number
            if head > state["last_block"]:
                for bn in range(state["last_block"] + 1, head + 1):
                    block = w3.eth.get_block(bn, full_transactions=True)

                    for tx in block.transactions:
                        tx_from = Web3.to_checksum_address(tx["from"])
                        tx_to   = Web3.to_checksum_address(tx["to"]) if tx["to"] else None
                        if not tx_to:
                            continue

                        # === Filter: alert ONLY when both addresses match ===
                        if tx_from == FROM_ADDR and tx_to == TO_ADDR:
                            tx_hash = tx["hash"].hex()
                            if tx_hash in state["seen"]:
                                continue

                            # --- Collect details/receipt ---
                            try:
                                receipt    = w3.eth.get_transaction_receipt(tx_hash)
                                status_ok  = (receipt.status == 1)
                                gas_used   = receipt.gasUsed
                                eff_price  = getattr(receipt, "effectiveGasPrice", tx.get("gasPrice", 0))
                                gas_fee_og = w3.from_wei(gas_used * eff_price, "ether")
                            except Exception:
                                status_ok, gas_used, gas_fee_og = None, None, None

                            method_id    = method_selector(tx.get("input"))
                            ts_utc       = fmt_time_utc(block.timestamp)
                            explorer_url = f"https://chainscan-galileo.0g.ai/tx/{tx_hash}"

                            status_emoji = "✅ Success" if status_ok else ("❌ Failed" if status_ok is not None else "⏳ Pending")

                            # --- Build a clean Telegram message ---
                            msg = (
                                f"🚨 *Transaction detected* on 0G Galileo\n"
                                f"Status: *{escape_md(status_emoji)}*\n"
                                f"Time: `{escape_md(ts_utc)}`\n\n"
                                f"From: `{escape_md(short_addr(FROM_ADDR))}`\n"
                                f"To:   `{escape_md(short_addr(TO_ADDR))}`\n"
                                f"Method: `{escape_md(method_id)}`\n"
                                f"Hash: [{escape_md(tx_hash)}]({escape_md(explorer_url)})\n\n"
                                f"Block: *{escape_md(bn)}*\n"
                                f"Value: {escape_md(fmt_num(w3.from_wei(tx['value'], 'ether')))} OG\n"
                                f"Gas Used: {escape_md(gas_used) if gas_used is not None else 'n/a'}\n"
                                f"Gas Fee: {escape_md(fmt_num(gas_fee_og)) if gas_fee_og is not None else 'n/a'} OG\n"
                                f"Nonce: {escape_md(tx['nonce'])}\n"
                            )
                            send_tg(msg)

                            # Remember this tx hash to avoid duplicate alerts
                            state["seen"].append(tx_hash)
                            if len(state["seen"]) > 500:
                                state["seen"] = state["seen"][-250:]

                state["last_block"] = head
                save_state(state)

        except Exception as e:
            print("Error in loop:", e)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

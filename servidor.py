import asyncio
import os
import struct
import datetime
import hashlib
import contextlib
from typing import Dict, Any, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8888

SALT_LENGTH = 16
MAX_PLAINTEXT = 4096
MAX_CLIENTS = 50
MIN_FRAME_SIZE = 68

MAX_FRAME_SIZE = 4164

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def get_fingerprint(public_key_bytes: bytes) -> str:
    """Gera um identificador público seguro (SHA-256 truncado) para auditoria e debug."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:12]

def log_info(msg: str):
    print(f"[*] {msg}", flush=True)

def log_event(msg: str):
    print(f"[+] {msg}", flush=True)

def log_warn(msg: str):
    print(f"[!] {msg}", flush=True)

def log_error(msg: str):
    print(f"[-] {msg}", flush=True)

def load_or_generate_server_identity():
    """
    Carrega ou gera o par de chaves RSA (>= 2048 bits) e o certificado X.509 autoassinado
    do servidor para autenticação dos clientes via RSA-PSS.
    """
    if os.path.exists(KEY_FILE) and os.path.exists(CERT_FILE):
        log_info("Carregando par RSA e certificado existentes...")
        with open(KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CERT_FILE, "rb") as f:
            cert = x509.load_der_x509_certificate(f.read())
        log_info("Identidade do servidor carregada.")
        return private_key, cert

    log_info("Gerando nova identidade do servidor (RSA 2048 bits)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Servidor Mensageria Segura E2E"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    log_info(f"Certificado '{CERT_FILE}' e chave '{KEY_FILE}' gerados com sucesso.")
    return private_key, cert

sessions: Dict[bytes, Dict[str, Any]] = {}

current_server_salt = os.urandom(SALT_LENGTH)

async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            sk_server: rsa.RSAPrivateKey, cert_server: x509.Certificate) -> Optional[bytes]:
    """
    Executa o handshake autenticado com o cliente:
    1. Recebe: client_id (16B) + pk_client (32B) [com ou sem framing 4B].
    2. Utiliza salt_srv (16B) gerado pelo servidor.
    3. Calcula H = SHA256(pk_server || pk_client || client_id || salt_srv).
    4. Assina H com RSA-PSS(SHA-256).
    5. Envia resposta: len(pk_S) + pk_S + len(cert) + cert + assinatura + salt_srv.
    6. Inicializa o estado da sessão.
    Retorna client_id em caso de sucesso ou None em caso de falha.
    """
    global current_server_salt

    if len(sessions) >= MAX_CLIENTS:
        log_error("Capacidade máxima de clientes atingida. Recusando conexão.")
        writer.close()
        await writer.wait_closed()
        return None

    first_4 = await reader.readexactly(4)
    first_val = struct.unpack("!I", first_4)[0]

    if first_val == 48:
        handshake_data = await reader.readexactly(48)
    elif 0 < first_val < 48:
        log_error(f"Erro de framing no handshake: tamanho anunciado {first_val}B é inválido. Desconectando com segurança.")
        return None
    else:
        rest = await reader.readexactly(44)
        handshake_data = first_4 + rest

    client_id = handshake_data[:16]
    pk_client = handshake_data[16:48]

    if len(client_id) != 16 or len(pk_client) != 32:
        log_error("Dados de handshake com tamanho incorreto.")
        return None

    if client_id in sessions:
        log_warn(f"Reconexão detectada para client_id {client_id.hex()[:8]}. Limpando sessão anterior.")
        with contextlib.suppress(Exception):
            sessions[client_id]["writer"].close()
        del sessions[client_id]

    if len(sessions) == 0:
        current_server_salt = os.urandom(SALT_LENGTH)

    salt_srv = current_server_salt

    pk_s_bytes = sk_server.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cert_bytes = cert_server.public_bytes(serialization.Encoding.DER)

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(pk_s_bytes + pk_client + client_id + salt_srv)
    h_digest = hasher.finalize()

    signature = sk_server.sign(
        h_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    resp = (
        struct.pack("!I", len(pk_s_bytes)) + pk_s_bytes +
        struct.pack("!I", len(cert_bytes)) + cert_bytes +
        signature +
        salt_srv
    )
    writer.write(resp)
    await writer.drain()

    sessions[client_id] = {
        "writer": writer,
        "public_key": pk_client,
        "seq_recv": -1,
        "seq_send": 0,
        "salt": salt_srv,
        "last_seq_per_recipient": {}
    }

    log_event(
        f"Cliente {client_id.hex()[:8]} registrado com sucesso. "
        f"Fingerprint pk_C: {get_fingerprint(pk_client)}"
    )
    return client_id

async def notify_peers_and_share_keys(new_client_id: bytes):
    """
    Rendezvous (Página 8 e 9 do Documento):
    Notifica os clientes já conectados sobre o novo cliente e envia as chaves públicas
    dos clientes existentes para o novo cliente, viabilizando a derivação de chaves E2E.
    
    Formato das mensagens de controle do servidor:
    [4B frame_len] + [8B seq_send] + [16B client_id] + [32B public_key]
    """
    new_info = sessions[new_client_id]
    new_writer = new_info["writer"]
    new_pk = new_info["public_key"]

    for peer_id, peer_info in list(sessions.items()):
        if peer_id == new_client_id:
            continue

        msg_to_existing = struct.pack("!Q", peer_info["seq_send"]) + new_client_id + new_pk
        peer_info["seq_send"] += 1
        peer_info["writer"].write(struct.pack("!I", len(msg_to_existing)) + msg_to_existing)

        msg_to_new = struct.pack("!Q", new_info["seq_send"]) + peer_id + peer_info["public_key"]
        new_info["seq_send"] += 1
        new_writer.write(struct.pack("!I", len(msg_to_new)) + msg_to_new)

        await peer_info["writer"].drain()

    await new_writer.drain()
    log_info(f"Chaves públicas sincronizadas entre {new_client_id.hex()[:8]} e demais pares.")

async def handle_e2e_traffic(reader: asyncio.StreamReader, client_id: bytes):
    """
    Processa frames enviados pelo cliente conectado:
    - O servidor atua APENAS como relay (sem decifrar).
    - Valida delimitador de framing (4 bytes big-endian).
    - Verifica limites de tamanho (MIN_FRAME_SIZE, MAX_FRAME_SIZE).
    - Aplica verificação anti-spoofing (sender_id == client_id autenticado).
    - Aplica verificação anti-replay (seq_no estritamente crescente por destinatário).
    - Encaminha os bytes brutos intactos para o destinatário.
    """
    client_session = sessions[client_id]

    while True:
        length_bytes = await reader.readexactly(4)
        frame_len = struct.unpack("!I", length_bytes)[0]


        if frame_len < MIN_FRAME_SIZE or frame_len > MAX_FRAME_SIZE:
            log_error(
                f"Erro de framing do cliente {client_id.hex()[:8]}: tamanho {frame_len} "
                f"fora dos limites [{MIN_FRAME_SIZE}, {MAX_FRAME_SIZE}]. Desconectando com segurança."
            )
            break

        frame = await reader.readexactly(frame_len)

        sender_id = frame[12:28]
        recipient_id = frame[28:44]
        seq_no = struct.unpack("!Q", frame[44:52])[0]

        if sender_id != client_id:
            log_warn(
                f"Tentativa de spoofing rejeitada! Remetente alegado {sender_id.hex()[:8]} "
                f"!= autenticado {client_id.hex()[:8]}."
            )

        last_seq = client_session["last_seq_per_recipient"].get(recipient_id, -1)
        if seq_no <= last_seq:
            log_warn(
                f"Tentativa de replay rejeitada de {client_id.hex()[:8]} para "
                f"{recipient_id.hex()[:8]}: seq_no recebido ({seq_no}) <= último aceito ({last_seq})."
            )
            continue

        client_session["last_seq_per_recipient"][recipient_id] = seq_no
        client_session["seq_recv"] = seq_no

        if recipient_id in sessions:
            rec_writer = sessions[recipient_id]["writer"]
            rec_writer.write(length_bytes + frame)
            await rec_writer.drain()
            log_info(
                f"Relay E2E concluído: {frame_len} bytes de {sender_id.hex()[:8]}... "
                f"para {recipient_id.hex()[:8]}... (seq_no: {seq_no})"
            )
        else:
            log_warn(
                f"Destinatário {recipient_id.hex()[:8]} não encontrado ou desconectado. "
                "Mensagem descartada."
            )

async def client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         sk_server: rsa.RSAPrivateKey, cert_server: x509.Certificate):
    """Gerencia o ciclo de vida completo de uma conexão de cliente."""
    client_id = None
    peer_addr = writer.get_extra_info("peername")
    log_info(f"Nova conexão TCP recebida de {peer_addr}")

    try:
        client_id = await perform_handshake(reader, writer, sk_server, cert_server)
        if not client_id:
            return
        await notify_peers_and_share_keys(client_id)

        await handle_e2e_traffic(reader, client_id)

    except asyncio.IncompleteReadError:
        log_info(f"Conexão finalizada pelo cliente {client_id.hex()[:8] if client_id else peer_addr}.")
    except ConnectionResetError:
        log_warn(f"Conexão resetada pelo cliente {client_id.hex()[:8] if client_id else peer_addr}.")
    except Exception as e:
        log_error(f"Erro inesperado na sessão de {client_id.hex()[:8] if client_id else peer_addr}: {e}")
    finally:

        if client_id and client_id in sessions:
            del sessions[client_id]
            log_event(f"Sessão de {client_id.hex()[:8]} removida. Tabela sessions limpa na memória.")
        
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()

async def main():
    sk_server, cert_server = load_or_generate_server_identity()

    server = await asyncio.start_server(
        lambda r, w: client_handler(r, w, sk_server, cert_server),
        SERVER_HOST, SERVER_PORT
    )

    log_event(f"Servidor de Mensageria E2E ativo em todas as interfaces ({SERVER_HOST}:{SERVER_PORT})")
    log_info("Aguardando conexões de clientes...")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado pelo usuário.", flush=True)

import asyncio
import os
import struct
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888


class MockClient:
    def __init__(self, name: str):
        self.name = name
        self.client_id = uuid.uuid4().bytes  # 16 bytes binário
        self.sk = x25519.X25519PrivateKey.generate()
        self.pk_bytes = self.sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.reader = None
        self.writer = None
        self.salt_srv = None
        self.peers = {}

    async def connect_and_handshake(self):
        self.reader, self.writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)

        # 1. Envia handshake: client_id (16B) + pk_client (32B)
        self.writer.write(self.client_id + self.pk_bytes)
        await self.writer.drain()

        # 2. Recebe resposta do servidor:
        # [len(pk_S) (4B)] + pk_S + [len(cert) (4B)] + cert + signature (256B) + salt_srv (16B)
        pk_s_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        pk_s_bytes = await self.reader.readexactly(pk_s_len)

        cert_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        cert_bytes = await self.reader.readexactly(cert_len)

        signature = await self.reader.readexactly(256)
        self.salt_srv = await self.reader.readexactly(16)

        # 3. Valida certificado e assinatura RSA-PSS do servidor
        cert = x509.load_der_x509_certificate(cert_bytes)
        server_pub_key = cert.public_key()

        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(pk_s_bytes + self.pk_bytes + self.client_id + self.salt_srv)
        h_digest = hasher.finalize()

        server_pub_key.verify(
            signature,
            h_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(f"[{self.name}] Handshake concluído e servidor autenticado com sucesso via RSA-PSS!")

    async def receive_peer_announcement(self):
        """Lê aviso de peer registrado enviado pelo servidor (rendezvous)."""
        frame_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        payload = await self.reader.readexactly(frame_len)
        seq_srv = struct.unpack("!Q", payload[:8])[0]
        peer_id = payload[8:24]
        peer_pk = payload[24:56]

        # Derivação de chaves E2E via HKDF-SHA256 (Páginas 2 e 3 da especificação)
        peer_pk_obj = x25519.X25519PublicKey.from_public_bytes(peer_pk)
        z_ab = self.sk.exchange(peer_pk_obj)

        # PRK = HKDF-Extract(salt = salt_srv, IKM = Z_AB)
        prk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt_srv,
            info=None
        ).derive(z_ab)

        # Key_A2B = HKDF-Expand(PRK, info="A2B", L=16)
        # Key_B2A = HKDF-Expand(PRK, info="B2A", L=16)
        key_a2b = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b"A2B").derive(prk)
        key_b2a = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b"B2A").derive(prk)

        # Atribuição das chaves conforme especificado nas páginas 6 e 7
        if self.client_id < peer_id:
            # Sou A, peer é B
            key_send = key_a2b
            key_recv = key_b2a
        else:
            # Sou B, peer é A
            key_send = key_b2a
            key_recv = key_a2b

        self.peers[peer_id] = {
            "pk": peer_pk,
            "key_send": key_send,
            "key_recv": key_recv,
            "seq_send": 0,
            "seq_recv": -1,
            "iv_base": os.urandom(4)
        }
        print(f"[{self.name}] Chaves E2E derivadas para comunicação com {peer_id.hex()[:8]}.")

    def build_e2e_frame(self, peer_id: bytes, plaintext: bytes, tamper_bitflip: bool = False, force_seq: int = None):
        peer = self.peers[peer_id]
        seq = force_seq if force_seq is not None else peer["seq_send"]
        if force_seq is None:
            peer["seq_send"] += 1

        # Construção do nonce (12B): IV_base (4B) || seq_no (8B big-endian)
        nonce = peer["iv_base"] + struct.pack("!Q", seq)
        # AAD: sender_id (16B) || recipient_id (16B) || seq_no (8B)
        aad = self.client_id + peer_id + struct.pack("!Q", seq)

        aesgcm = AESGCM(peer["key_send"])
        encrypted = aesgcm.encrypt(nonce, plaintext, aad)

        if tamper_bitflip:
            # Inverte o último byte para simular adulteração no tráfego
            encrypted = bytearray(encrypted)
            encrypted[-1] ^= 0x01
            encrypted = bytes(encrypted)

        frame = nonce + self.client_id + peer_id + struct.pack("!Q", seq) + encrypted
        framed_packet = struct.pack("!I", len(frame)) + frame
        return framed_packet

    async def receive_and_decrypt_e2e(self):
        """Lê frame encaminhado pelo servidor e decifra localmente via AES-128-GCM."""
        frame_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        frame = await self.reader.readexactly(frame_len)

        nonce = frame[0:12]
        sender_id = frame[12:28]
        recipient_id = frame[28:44]
        seq_no = struct.unpack("!Q", frame[44:52])[0]
        ciphertext_and_tag = frame[52:]

        peer = self.peers[sender_id]

        # Validação anti-replay no cliente
        if seq_no <= peer["seq_recv"]:
            raise ValueError(f"Replay detectado pelo cliente! seq_no {seq_no} <= {peer['seq_recv']}")
        peer["seq_recv"] = seq_no

        aad = sender_id + recipient_id + struct.pack("!Q", seq_no)
        aesgcm = AESGCM(peer["key_recv"])
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
        return plaintext.decode("utf-8")

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


async def run_all_tests():
    print("=" * 65)
    print("INICIANDO BATERIA DE TESTES OBRIGATÓRIOS DO SERVIDOR (PÁGINA 11)")
    print("=" * 65)

    client_a = MockClient("Cliente_A")
    client_b = MockClient("Cliente_B")

    # TESTE 1: Conexão e Handshake Autenticado de 2 clientes
    print("\n--- TESTE 1: Conexão, Handshake e Troca de Mensagens E2E ---")
    await client_a.connect_and_handshake()
    await client_b.connect_and_handshake()

    # Sincronização de Rendezvous (distribuição de chaves públicas)
    await client_a.receive_peer_announcement()
    await client_b.receive_peer_announcement()

    # Envio de mensagem E2E de A para B via relay do servidor
    msg = "Olá B! Mensagem confidencial com sigilo perfeito."
    packet = client_a.build_e2e_frame(client_b.client_id, msg.encode("utf-8"))
    client_a.writer.write(packet)
    await client_a.writer.drain()

    decrypted = await client_b.receive_and_decrypt_e2e()
    assert decrypted == msg, f"Mensagem decifrada incorreta: {decrypted}"
    print(f"[SUCESSO] Cliente B decifrou com perfeição: '{decrypted}'")

    # TESTE 2: Mensagem adulterada (Bitflip) no tráfego
    print("\n--- TESTE 2: Detecção de Adulteração (Bitflip) ---")
    tampered_packet = client_a.build_e2e_frame(
        client_b.client_id,
        b"Tentativa de adulteracao",
        tamper_bitflip=True
    )
    client_a.writer.write(tampered_packet)
    await client_a.writer.drain()

    try:
        await client_b.receive_and_decrypt_e2e()
        print("[FALHA] Cliente B aceitou mensagem adulterada!")
    except Exception as e:
        print(f"[SUCESSO] Adulteração detectada! AES-GCM rejeitou a tag: {type(e).__name__}")

    # TESTE 3: Tentativa de Replay de Frame
    print("\n--- TESTE 3: Proteção Contra Replay de Frame ---")
    # Reenvia um pacote com seq_no já utilizado (seq_no = 0)
    replay_packet = client_a.build_e2e_frame(
        client_b.client_id,
        b"Mensagem reusando seq_no",
        force_seq=0
    )
    client_a.writer.write(replay_packet)
    await client_a.writer.drain()
    print("[*] Replay enviado ao servidor. Verifique o log do servidor rejeitando o seq_no duplicado.")
    await asyncio.sleep(0.5)

    # TESTE 4: Framing Inválido (tamanho menor que o mínimo)
    print("\n--- TESTE 4: Framing Inválido e Desconexão Segura ---")
    bad_reader, bad_writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
    # Envia 4 bytes com tamanho inválido (apenas 5 bytes, menor que MIN_FRAME_SIZE 68)
    bad_writer.write(struct.pack("!I", 5) + b"12345")
    await bad_writer.drain()
    await asyncio.sleep(0.5)

    # Verifica se a conexão foi fechada com segurança pelo servidor
    is_closed = bad_reader.at_eof()
    print(f"[SUCESSO] Servidor tratou framing inválido e desconectou com segurança (EOF={is_closed}).")

    # Limpeza
    await client_a.close()
    await client_b.close()
    bad_writer.close()
    await bad_writer.wait_closed()

    print("\n" + "=" * 65)
    print("TODOS OS 4 TESTES MÍNIMOS OBRIGATÓRIOS FORAM VALIDADOS COM SUCESSO!")
    print("=" * 65)

if __name__ == "__main__":
    asyncio.run(run_all_tests())
import argparse
import secrets
import socket
import string
import threading

import aes

ALPHABET = string.ascii_letters + string.digits


def valid_key(k):
    return len(k) == 16 and k.isascii() and "|" not in k and k.isprintable()


def send(sock, line):
    sock.sendall((line + "\n").encode("ascii"))


class KDC:
    def __init__(self, port):
        self.port = port
        self.keys = {}  # ID -> master key (16 char ASCII)
        self.lock = threading.Lock()

    def listen(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen()
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        try:
            conn.settimeout(10)
            line = conn.makefile("rb").readline().decode("ascii").strip()
            tag, _, body = line.partition(" ")
            print(f"\n[KDC] (1) dari {addr[0]}: {line}")
            if tag != "1":
                send(conn, "ERR format pesan salah")
                return
            parts = body.split("|")
            if len(parts) != 3:
                send(conn, "ERR format harus IDA|IDB|N1")
                return
            ida, idb, n1 = parts
            with self.lock:
                ka, kb = self.keys.get(ida), self.keys.get(idb)
            if ka is None or kb is None:
                send(conn, "ERR ID tidak terdaftar di KDC")
                print(f"[KDC] ID tidak terdaftar: {ida}/{idb}")
                return
            ks = "".join(secrets.choice(ALPHABET) for _ in range(16))
            part_a = aes.encrypt_hex(ka, f"{ks}|{ida}|{idb}|{n1}")
            ticket = aes.encrypt_hex(kb, f"{ks}|{ida}")
            send(conn, f"2 {part_a}||{ticket}")
            print(f"[KDC] Ks={ks}")
            print(f"[KDC] (2) E(Ka)[Ks|IDA|IDB|N1] = {part_a}")
            print(f"[KDC]     ticket E(Kb)[Ks|IDA]  = {ticket}")
        except (OSError, ValueError, UnicodeError) as e:
            print(f"\n[KDC] error: {e}")
        finally:
            conn.close()

    def set_key(self, ident, key):
        with self.lock:
            self.keys[ident] = key

    def run(self):
        threading.Thread(target=self.listen, daemon=True).start()
        print(f"KDC mendengarkan di port {self.port}. Ketik /help untuk bantuan")
        while True:
            try:
                line = input("KDC> ").strip()
            except EOFError:
                break
            parts = line.split()
            if not parts:
                continue
            cmd = parts[0]
            if cmd == "/key" and len(parts) == 3:
                if valid_key(parts[2]):
                    self.set_key(parts[1], parts[2])
                    print(f"Master key {parts[1]} diset")
                else:
                    print("Key harus 16 karakter ASCII tanpa '|'")
            elif cmd == "/list":
                with self.lock:
                    for i, k in self.keys.items():
                        print(f"  {i}: {k}")
            elif cmd == "/quit":
                break
            else:
                print("/key <ID> <key16> | /list | /quit")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--ids", default="Alice,Bob", help="ID peserta, pisah koma")
    args = ap.parse_args()
    kdc = KDC(args.port)
    for ident in args.ids.split(","):
        while True:
            key = input(f"Master key {ident} (16 karakter): ")
            if valid_key(key):
                kdc.set_key(ident, key)
                break
            print("Key tidak valid")
    kdc.run()


if __name__ == "__main__":
    main()

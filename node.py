import argparse
import secrets
import socket
import threading

import aes


def send(sock, line):
    sock.sendall((line + "\n").encode("ascii"))


def read_msg(rfile):
    line = rfile.readline().decode("ascii").strip()
    if not line:
        raise ConnectionError("koneksi terputus")
    tag, _, body = line.partition(" ")
    return tag, body


class Node:
    def __init__(self, my_id, key, kdc, port):
        self.id = my_id
        self.key = key
        self.kdc = kdc
        self.port = port
        self.sess = None
        self.lock = threading.Lock()

    def listen(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen()
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.respond, args=(conn, addr), daemon=True).start()

    def respond(self, conn, addr):
        rfile = conn.makefile("rb")
        try:
            tag, body = read_msg(rfile)
            if tag != "3":
                raise ValueError("pesan langkah 3 tidak ditemukan")
            print(f"\n[{self.id}] (3) dari {addr[0]}: {body}")
            ks, peer = aes.decrypt_hex(self.key, body).split("|")
            n2 = secrets.randbelow(10 ** 9)
            c4 = aes.encrypt_hex(ks, str(n2))
            send(conn, "4 " + c4)
            print(f"[{self.id}] (4) N2={n2} -> {c4}")
            tag, body = read_msg(rfile)
            if tag != "5":
                raise ValueError("pesan langkah 5 tidak ditemukan")
            print(f"[{self.id}] (5) {body}")
            if int(aes.decrypt_hex(ks, body)) != n2 + 1:
                raise ValueError("autentikasi gagal, f(N2) salah")
            self.start_session(conn, rfile, ks, peer)
        except (ValueError, OSError) as e:
            print(f"\n[{self.id}] handshake gagal: {e}")
            conn.close()

    def connect(self, peer_id, host, port):
        n1 = secrets.randbelow(10 ** 9)
        k = socket.create_connection(self.kdc, timeout=5)
        kf = k.makefile("rb")
        send(k, f"1 {self.id}|{peer_id}|{n1}")
        print(f"[{self.id}] (1) ke KDC: {self.id}|{peer_id}|{n1}")
        tag, body = read_msg(kf)
        k.close()
        if tag != "2":
            raise ConnectionError(f"KDC menolak: {body}")
        print(f"[{self.id}] (2) dari KDC: {body}")
        part_a, ticket = body.split("||")
        ks, ida, idb, n1r = aes.decrypt_hex(self.key, part_a).split("|")
        if (ida, idb, n1r) != (self.id, peer_id, str(n1)):
            raise ValueError("balasan KDC tidak cocok (ID/nonce salah)")

        s = socket.create_connection((host, port), timeout=5)
        sf = s.makefile("rb")
        try:
            send(s, "3 " + ticket)
            print(f"[{self.id}] (3) ke {peer_id}: {ticket}")
            tag, body = read_msg(sf)
            if tag != "4":
                raise ValueError("pesan langkah 4 tidak ditemukan")
            n2 = int(aes.decrypt_hex(ks, body))
            print(f"[{self.id}] (4) dari {peer_id}: N2={n2}")
            c5 = aes.encrypt_hex(ks, str(n2 + 1))
            send(s, "5 " + c5)
            print(f"[{self.id}] (5) ke {peer_id}: {c5}")
        except Exception:
            s.close()
            raise
        s.settimeout(None)
        self.start_session(s, sf, ks, peer_id)

    def start_session(self, sock, rfile, ks, peer):
        with self.lock:
            old = self.sess
            self.sess = {"sock": sock, "ks": ks, "peer": peer}
        if old:
            old["sock"].close()
        print(f"\n[+] Sesi dengan {peer} terbentuk, Ks={ks}")
        threading.Thread(target=self.recv_loop, args=(sock, rfile, ks, peer), daemon=True).start()

    def recv_loop(self, sock, rfile, ks, peer):
        try:
            while True:
                tag, body = read_msg(rfile)
                if tag != "MSG":
                    continue
                try:
                    text = aes.decrypt_hex(ks, body)
                except ValueError:
                    print(f"\n[!] pesan dari {peer} gagal didekripsi")
                    continue
                print(f"\n[{peer}] {text}\n   cipher(hex): {body}")
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                if self.sess and self.sess["sock"] is sock:
                    self.sess = None
            sock.close()
            print(f"\n[-] Sesi dengan {peer} ditutup")

    def send_msg(self, text):
        with self.lock:
            sess = self.sess
        if not sess:
            print("Belum ada sesi. Gunakan /connect")
            return
        try:
            c = aes.encrypt_hex(sess["ks"], text)
        except UnicodeEncodeError:
            print("Pesan harus ASCII")
            return
        send(sess["sock"], "MSG " + c)
        print(f"   cipher(hex): {c}")

    def run(self):
        threading.Thread(target=self.listen, daemon=True).start()
        print(f"{self.id} mendengarkan di port {self.port}. Ketik /help untuk bantuan")
        while True:
            try:
                line = input(f"{self.id}> ").strip()
            except EOFError:
                break
            if not line:
                continue
            if not line.startswith("/"):
                self.send_msg(line)
                continue
            parts = line.split()
            cmd = parts[0]
            if cmd == "/connect" and len(parts) == 4:
                try:
                    self.connect(parts[1], parts[2], int(parts[3]))
                except (OSError, ValueError) as e:
                    print(f"Gagal: {e}")
            elif cmd == "/key" and len(parts) == 2:
                if len(parts[1]) == 16 and parts[1].isascii() and "|" not in parts[1]:
                    self.key = parts[1]
                    print("Master key diganti")
                else:
                    print("Key harus 16 karakter ASCII tanpa '|'")
            elif cmd == "/status":
                with self.lock:
                    s = self.sess
                print(f"Master key: {self.key}")
                print(f"Sesi: {s['peer']} (Ks={s['ks']})" if s else "Sesi: tidak ada")
            elif cmd == "/quit":
                break
            else:
                print("/connect <ID> <ip> <port> | /key <key16> | /status | /quit")
                print("Teks tanpa awalan / dikirim sebagai pesan terenkripsi")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--kdc", required=True, help="ip:port KDC")
    args = ap.parse_args()
    host, _, p = args.kdc.partition(":")
    while True:
        key = input(f"Master key {args.id} (16 karakter): ")
        if len(key) == 16 and key.isascii() and "|" not in key:
            break
        print("Key tidak valid")
    Node(args.id, key, (host, int(p)), args.port).run()


if __name__ == "__main__":
    main()

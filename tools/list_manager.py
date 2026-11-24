# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fenster zum Hinzufuegen von Adresslisten zu den kuratierten Listen von PaperStream Intel.

Start: python3 tools/list_manager.py
"""
import ipaddress
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from datasets import Datasets  # noqa: E402

CURATED = ROOT / "curated"
CACHE = pathlib.Path.home() / ".cache" / "paperstream-intel-tool"
REMOTE_DATA = "/var/lib/paperstream-intel/datasets/."
IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?::\d{1,5})?(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?:/(\d{1,3}))?(?![0-9A-Fa-f:])")
MIN_PREFIX = {4: 8, 6: 19}


def parse(text):
    """Alle Adressen und Bereiche aus einem beliebigen Text. Gibt (gefunden, verworfen) zurueck."""
    found, dropped = set(), 0
    for pattern in (IPV4, IPV6):
        for match in pattern.finditer(text):
            address, prefix = match.group(1), match.group(2)
            try:
                if prefix is not None:
                    entry = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
                    ok = entry.is_global and entry.prefixlen >= MIN_PREFIX[entry.version]
                    value = str(entry)
                else:
                    entry = ipaddress.ip_address(address)
                    ok = entry.is_global
                    value = str(entry)
            except ValueError:
                dropped += 1
                continue
            if ok:
                found.add(value)
            else:
                dropped += 1
    return sorted(found, key=sort_key), dropped


def sort_key(value):
    network = ipaddress.ip_network(value, strict=False)
    return network.version, int(network.network_address), network.prefixlen


def flagged(result, only_vpn):
    if result["vpn"] or result["proxy"] or result["tor"]:
        return True
    return False if only_vpn else result["hosting"]


def is_known(data, value, only_vpn=False):
    """Ein Bereich gilt als bekannt, wenn sein erster und letzter Eintrag schon erkannt werden."""
    network = ipaddress.ip_network(value, strict=False)
    ends = {network[0], network[-1]}
    return all(flagged(data.lookup(address), only_vpn) for address in ends)


def split_new(data, entries, only_vpn=False):
    new = [entry for entry in entries if not is_known(data, entry, only_vpn)]
    return new, len(entries) - len(new)


def safe_name(name):
    name = re.sub(r"[^a-z0-9-]+", "-", name.strip().lower()).strip("-")
    return name or "list"


def add_entries(name, entries, directory=CURATED):
    """Schreibt die Eintraege in curated/<name>.txt, ohne doppelte. Gibt (Pfad, neu dazugekommen) zurueck."""
    directory.mkdir(exist_ok=True)
    path = directory / f"{safe_name(name)}.txt"
    existing = set()
    if path.exists():
        existing = {line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")}
    merged = existing | set(entries)
    path.write_text("\n".join(sorted(merged, key=sort_key)) + "\n")
    return path, len(merged) - len(existing)


def server_settings():
    settings = {}
    for line in (ROOT / "deploy" / "local.env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip().strip('"').strip("'")
    return settings["DEPLOY_KEY"], f"root@{settings['DEPLOY_IP']}"


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[-400:] or f"Fehler {result.returncode}")
    return result.stdout.strip()


def fetch_data():
    key, host = server_settings()
    CACHE.mkdir(parents=True, exist_ok=True)
    run(["scp", "-q", "-r", "-i", os.path.expanduser(key), f"{host}:{REMOTE_DATA}", str(CACHE)])


def deploy():
    key, host = server_settings()
    key = os.path.expanduser(key)
    pack = subprocess.Popen(["tar", "-C", str(ROOT), "-czf", "-", "curated"], stdout=subprocess.PIPE)
    unpack = subprocess.run(["ssh", "-i", key, host, "tar -C /opt/paperstream-intel -xzf - && chown -R root:root "
                             "/opt/paperstream-intel/curated && systemctl restart paperstream-intel && sleep 3 && "
                             "systemctl is-active paperstream-intel"], stdin=pack.stdout, capture_output=True, text=True)
    pack.wait()
    if unpack.returncode or "active" not in unpack.stdout:
        raise RuntimeError((unpack.stderr or unpack.stdout).strip()[-400:])
    return unpack.stdout.strip()


def commit_and_push(message):
    run(["git", "-C", str(ROOT), "add", "curated"])
    status = run(["git", "-C", str(ROOT), "status", "--porcelain", "curated"])
    if not status:
        return "Nichts zu committen"
    run(["git", "-C", str(ROOT), "commit", "-q", "-m", message])
    run(["git", "-C", str(ROOT), "push", "codeberg", "HEAD"])
    run(["git", "-C", str(ROOT), "-c", "credential.helper=!gh auth git-credential", "push", "github", "HEAD"])
    return "Committet und auf Codeberg und GitHub gepusht"


def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    window = tk.Tk()
    window.title("PaperStream Intel Listen")
    window.geometry("820x760")
    back, front, field, accent = "#14171f", "#e4e7ee", "#1e2230", "#3fc1a8"
    window.configure(bg=back)
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=back, foreground=front, fieldbackground=field, bordercolor="#2c3245",
                    lightcolor=back, darkcolor=back, troughcolor=field, focuscolor=back)
    style.configure("TButton", background="#262c3f", foreground=front, padding=6)
    style.map("TButton", background=[("active", accent)], foreground=[("active", "#0b0e14")])
    style.configure("TRadiobutton", background=back, foreground=front)
    style.map("TRadiobutton", background=[("active", back)], indicatorcolor=[("selected", accent)])
    style.configure("TEntry", fieldbackground=field, foreground=front, insertcolor=front)

    def text_box(parent, height):
        return scrolledtext.ScrolledText(parent, height=height, bg=field, fg=front, insertbackground=front,
                                         selectbackground=accent, selectforeground="#0b0e14", relief="flat",
                                         highlightthickness=1, highlightbackground="#2c3245")
    messages = queue.Queue()
    state = {"data": None, "new": [], "entries": []}

    def log(text):
        messages.put(text)

    def pump():
        while not messages.empty():
            output.insert("end", messages.get() + "\n")
            output.see("end")
        window.after(150, pump)

    def background(work):
        def target():
            try:
                work()
            except Exception as error:  # noqa: BLE001
                log(f"FEHLER: {error}")
        threading.Thread(target=target, daemon=True).start()

    def load_data():
        def work():
            log("Hole die aktuellen Daten vom Server ...")
            fetch_data()
            state["data"] = Datasets(CACHE)
            log(f"Daten geladen: {state['data'].summary()['feed_ranges']} Netze im Feed, "
                f"{state['data'].summary()['vpn_ranges']} VPN-Bereiche.")
        background(work)

    def read_into_box(path):
        try:
            content = path.read_text(errors="replace")
        except OSError as error:
            log(f"FEHLER: {path}: {error}")
            return
        box.insert("end", content + "\n")
        if not name.get():
            name.set(safe_name(path.stem))
        log(f"Geladen: {path.name}")

    def load_path(event=None):
        # Pfade getrennt durch Zeilenumbruch oder Semikolon, Ordner laden alle Textdateien darin
        for raw in re.split(r"[;\n]", path_text.get()):
            raw = raw.strip().strip("\"'")
            if not raw:
                continue
            path = pathlib.Path(os.path.expanduser(raw))
            if path.is_dir():
                files = sorted(f for f in path.iterdir() if f.suffix.lower() in (".txt", ".csv", ".json", ".list"))
                log(f"{path}: {len(files)} Dateien")
                for file in files:
                    read_into_box(file)
            elif path.is_file():
                read_into_box(path)
            else:
                log(f"FEHLER: {path} gibt es nicht")
        path_text.set("")

    def browse():
        for chosen in filedialog.askopenfilenames(title="Listen auswaehlen", initialdir=os.path.expanduser("~/Downloads")):
            read_into_box(pathlib.Path(chosen))

    def check():
        if state["data"] is None:
            log("Die Serverdaten sind noch nicht geladen.")
            return
        entries, dropped = parse(box.get("1.0", "end"))
        new, known = split_new(state["data"], entries, only_vpn.get() == 1)
        state["entries"], state["new"] = entries, new
        summary.set(f"Gefunden: {len(entries)}   schon erkannt: {known}   NEU: {len(new)}   verworfen: {dropped}")
        result.delete("1.0", "end")
        result.insert("end", "\n".join(new))
        log(summary.get())

    def add():
        if not state["new"]:
            log("Nichts Neues zum Hinzufuegen (erst pruefen).")
            return
        path, count = add_entries(name.get(), state["new"])
        log(f"{count} Eintraege in {path.relative_to(ROOT)} geschrieben.")
        state["new"] = []

    def send():
        if messagebox.askyesno("Auf den Server", "Die kuratierten Listen jetzt auf den Server kopieren und den Dienst neu starten?"):
            background(lambda: log("Server: " + deploy()))

    def push():
        text = message.get().strip()
        if not text:
            log("Commit-Text fehlt.")
            return
        if messagebox.askyesno("Pushen", f"Committen und auf Codeberg und GitHub pushen?\n\n{text}"):
            background(lambda: log(commit_and_push(text)))

    frame = ttk.Frame(window, padding=10)
    frame.pack(fill="both", expand=True)
    top = ttk.Frame(frame)
    top.pack(fill="x")
    ttk.Label(top, text="Name der Liste:").pack(side="left")
    name = tk.StringVar()
    ttk.Entry(top, textvariable=name, width=24).pack(side="left", padx=6)
    ttk.Button(top, text="Serverdaten neu holen", command=load_data).pack(side="right")
    paths = ttk.Frame(frame)
    paths.pack(fill="x", pady=(8, 0))
    ttk.Label(paths, text="Pfad:").pack(side="left")
    path_text = tk.StringVar()
    path_entry = ttk.Entry(paths, textvariable=path_text)
    path_entry.pack(side="left", fill="x", expand=True, padx=6)
    path_entry.bind("<Return>", load_path)
    ttk.Button(paths, text="Laden", command=load_path).pack(side="left")
    ttk.Button(paths, text="...", width=3, command=browse).pack(side="left", padx=(6, 0))
    ttk.Label(frame, text="Adressen (Pfad eintippen, Ordner geht auch, oder hier einfuegen):").pack(anchor="w", pady=(8, 2))
    box = text_box(frame, 10)
    box.pack(fill="both", expand=True)
    options = ttk.Frame(frame)
    options.pack(fill="x", pady=6)
    only_vpn = tk.IntVar(value=0)
    ttk.Radiobutton(options, text="Neu = noch nicht als VPN, Proxy, Tor oder Hosting erkannt", variable=only_vpn, value=0).pack(anchor="w")
    ttk.Radiobutton(options, text="Neu = noch nicht als VPN, Proxy oder Tor erkannt (Hosting zaehlt nicht)", variable=only_vpn, value=1).pack(anchor="w")
    ttk.Button(frame, text="1. Pruefen", command=check).pack(anchor="w")
    summary = tk.StringVar(value="Noch nicht geprueft.")
    ttk.Label(frame, textvariable=summary).pack(anchor="w", pady=4)
    result = text_box(frame, 7)
    result.pack(fill="both", expand=True)
    steps = ttk.Frame(frame)
    steps.pack(fill="x", pady=8)
    ttk.Button(steps, text="2. Neue hinzufuegen", command=add).pack(side="left")
    ttk.Button(steps, text="3. Auf den Server", command=send).pack(side="left", padx=8)
    message = tk.StringVar(value="Add list of addresses")
    ttk.Button(steps, text="4. Commit + Push", command=push).pack(side="right")
    ttk.Entry(steps, textvariable=message, width=34).pack(side="right", padx=6)
    output = text_box(frame, 8)
    output.pack(fill="both", expand=True)
    pump()
    load_data()
    window.mainloop()


if __name__ == "__main__":
    main()

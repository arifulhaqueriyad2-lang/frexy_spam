import os, time, json, random, socket, threading, asyncio, sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import authentication functions
from JwtGen import (
    GeNeRaTeAccEss, EncRypTMajoRLoGin, MajorLogin, DecRypTMajoRLoGin,
    GetLoginData, DecRypTLoGinDaTa, xAuThSTarTuP
)

# ---------- SQLite Database Initialization ----------
DB_PATH = "frexy.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    # Default Admin account setup if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'frexy'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('frexy', 'frexyspam', 1)")
    conn.commit()
    conn.close()

init_db()

# ---------- Global data ----------
connected_clients = {}          # uid -> client object (Shared bots)
connected_clients_lock = threading.Lock()

# Multi-tenant isolation: Structure changes to { username: { target_uid: timestamp } }
active_spam_targets = {}        
active_spam_lock = threading.Lock()

# ---------- Packet functions ----------
def EnC_Uid(H):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0))
        H >>= 7
    return bytes(e).hex()

def CrEaTe_ProTo(fields):
    def EnC_Vr(N):
        if N < 0:
            return b''
        H = []
        while True:
            b = N & 0x7F
            N >>= 7
            if N:
                b |= 0x80
            H.append(b)
            if not N:
                break
        return bytes(H)
    def CrEaTe_VarianT(field_number, value):
        field_header = (field_number << 3) | 0
        return EnC_Vr(field_header) + EnC_Vr(value)
    def CrEaTe_LenGTh(field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

def GeneRaTePk(Pk, N, K, V):
    def EnC_PacKeT(HeX, K, V):
        return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()
    def DecodE_HeX(H):
        return hex(H)[2:].zfill(2)
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(len(PkEnc) // 2)
    if len(_) == 2:
        HeadEr = N + "000000"
    elif len(_) == 3:
        HeadEr = N + "00005"
    elif len(_) == 4:
        HeadEr = N + "0000"
    elif len(_) == 5:
        HeadEr = N + "000"
    else:
        HeadEr = N + "000000"
    return bytes.fromhex(HeadEr + _ + PkEnc)

def openroom(K, V):
    fields = {
        1: 2,
        2: {
            1: 1, 2: 15, 3: 5, 4: "[FFFF00][b]FREXY", 5: "1", 6: 12, 7: 1, 8: 1, 9: 1,
            11: 1, 12: 2, 14: 36981056,
            15: {1: "IDC3", 2: 126, 3: "ME"},
            16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
            18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
            49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}
        }
    }
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

def spmroom(K, V, uid):
    fields = {1: 22, 2: {1: int(uid)}}
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

# ---------- Optimized Spam worker with isolated check ----------
def is_target_active(target_id, owner_username):
    with active_spam_lock:
        return owner_username in active_spam_targets and target_id in active_spam_targets[owner_username]

def send_spam_from_all_accounts(target_id, owner_username):
    with connected_clients_lock:
        clients = list(connected_clients.values())
    for client in clients:
        if not is_target_active(target_id, owner_username):
            break
        if not client.online_sock or client._need_reconnect:
            client.reconnect()
            if not client.online_sock:
                continue
        try:
            client.online_sock.send(openroom(client.key, client.iv))
            time.sleep(0.5)
            for i in range(10):
                if not is_target_active(target_id, owner_username):
                    break
                client.online_sock.send(spmroom(client.key, client.iv, target_id))
                time.sleep(0.15)
        except (BrokenPipeError, OSError):
            client._need_reconnect = True
        except Exception:
            pass

def spam_worker(target_id, duration_minutes, owner_username):
    start_time = datetime.now()
    while is_target_active(target_id, owner_username):
        if duration_minutes:
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed >= duration_minutes * 60:
                with active_spam_lock:
                    if owner_username in active_spam_targets and target_id in active_spam_targets[owner_username]:
                        del active_spam_targets[owner_username][target_id]
                break
        try:
            send_spam_from_all_accounts(target_id, owner_username)
            # Short sleep chunks to stop instantly
            for _ in range(15):
                if not is_target_active(target_id, owner_username):
                    break
                time.sleep(1)
        except Exception:
            time.sleep(1)

# ---------- Account client with auto-reconnect ----------
class FF_CLient:
    def __init__(self, uid, password):
        self.uid = uid
        self.password = password
        self.key = None
        self.iv = None
        self.auth_token = None
        self.online_sock = None
        self.running = False
        self._need_reconnect = False
        self._connect()

    def _run_async(self, coro):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def _full_auth(self):
        try:
            open_id, access_token = self._run_async(GeNeRaTeAccEss(self.uid, self.password))
            if not open_id or not access_token:
                return False
            payload = self._run_async(EncRypTMajoRLoGin(open_id, access_token))
            login_res = self._run_async(MajorLogin(payload))
            if not login_res:
                return False
            dec = self._run_async(DecRypTMajoRLoGin(login_res))
            self.key = dec.key
            self.iv = dec.iv
            token = dec.token
            timestamp = dec.timestamp
            account_uid = dec.account_uid
            login_data = self._run_async(GetLoginData(dec.url, payload, token))
            if not login_data:
                return False
            ports = self._run_async(DecRypTLoGinDaTa(login_data))
            online_ip, online_port = ports.Online_IP_Port.split(":")
            self.online_ip = online_ip
            self.online_port = int(online_port)
            self.auth_token = self._run_async(xAuThSTarTuP(
                int(account_uid), token, int(timestamp), self.key, self.iv
            ))
            return True
        except Exception:
            return False

    def _connect_online(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.online_ip, self.online_port))
            sock.send(bytes.fromhex(self.auth_token))
            resp = sock.recv(4096)
            if not resp:
                sock.close()
                return None
            return sock
        except Exception:
            return None

    def _reader(self, sock):
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
            except Exception:
                break
        self.running = False
        self._need_reconnect = True

    def _connect(self):
        if not self._full_auth():
            return
        sock = self._connect_online()
        if not sock:
            return
        self.online_sock = sock
        self.running = True
        self._need_reconnect = False
        threading.Thread(target=self._reader, args=(sock,), daemon=True).start()
        with connected_clients_lock:
            connected_clients[self.uid] = self

    def reconnect(self):
        if self.online_sock:
            try:
                self.online_sock.close()
            except Exception:
                pass
        self.running = False
        self._connect()

# ---------- Load accounts from Eren.txt ----------
def load_accounts():
    accounts = []
    try:
        with open("Eren.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    uid, pwd = line.split(":", 1)
                    accounts.append((uid, pwd))
    except FileNotFoundError:
        pass
    return accounts

def start_all_accounts():
    for uid, pwd in load_accounts():
        threading.Thread(target=lambda: FF_CLient(uid, pwd), daemon=True).start()
        time.sleep(3)

# ---------- Flask Config & Session Middleware ----------
app = Flask(__name__)
app.secret_key = "frexy_secret_key_encryption"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------- View Templates ----------

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FREXY ULTRA SPAM - LOGIN</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;900&family=Rajdhani:wght@600;700&display=swap" rel="stylesheet">
    <style>
        body {
            background: radial-gradient(circle at center, #0a1128 0%, #020514 100%);
            font-family: 'Rajdhani', sans-serif;
        }
        .glow-cyan {
            text-shadow: 0 0 15px rgba(0, 240, 255, 0.6);
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-black/40 backdrop-blur-md border border-cyan-500/20 rounded-2xl p-8 shadow-2xl">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-black text-cyan-400 font-sans tracking-wider uppercase glow-cyan">
                FREXY LOGIN
            </h1>
            <p class="text-xs text-slate-400 tracking-widest uppercase mt-2">Enter your core database credentials</p>
        </div>

        {% if error %}
        <div class="bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl p-3 text-sm text-center mb-6 font-mono">
            {{ error }}
        </div>
        {% endif %}

        <form method="POST" class="space-y-5">
            <div>
                <label class="text-xs text-cyan-400 font-bold uppercase tracking-wider block mb-2">Username</label>
                <input type="text" name="username" class="w-full bg-slate-900/80 border border-slate-800 rounded-xl py-3 px-4 text-white focus:outline-none focus:border-cyan-400 transition" required>
            </div>
            <div>
                <label class="text-xs text-cyan-400 font-bold uppercase tracking-wider block mb-2">Password</label>
                <input type="password" name="password" class="w-full bg-slate-900/80 border border-slate-800 rounded-xl py-3 px-4 text-white focus:outline-none focus:border-cyan-400 transition" required>
            </div>
            <button type="submit" class="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold py-3.5 rounded-xl uppercase tracking-widest hover:opacity-90 shadow-lg shadow-cyan-500/20 transition mt-2">
                Access System
            </button>
        </form>
    </div>
</body>
</html>
'''

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>FREXY ULTRA SPAM v3.0</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;900&family=Rajdhani:wght@500;600;700&family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">

    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        cyberCyan: '#00f0ff',
                        darkBlue: '#03081e',
                        deepNavy: '#01040f',
                    }
                }
            }
        }
    </script>

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Rajdhani', sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background: radial-gradient(circle at top, #061129 0%, #02050f 100%);
            color: #ffffff;
            min-height: 100vh;
        }

        .neon-glow-cyan {
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.6), 0 0 20px rgba(0, 240, 255, 0.3);
        }

        .stat-box {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.08) 0%, rgba(3, 8, 30, 0.8) 100%);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 16px;
            text-align: center;
            padding: 18px 12px;
            box-shadow: 0 4px 20px rgba(0, 240, 255, 0.05);
            transition: all 0.3s ease;
        }
        .stat-box:hover {
            border-color: #00f0ff;
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.25);
            transform: translateY(-2px);
        }

        .stat-val {
            font-size: 2.6rem;
            font-weight: 800;
            color: #00f0ff;
            text-shadow: 0 0 15px rgba(0, 240, 255, 0.6);
            line-height: 1;
            font-family: 'Orbitron', sans-serif;
        }

        .cyber-link-btn {
            background: rgba(0, 240, 255, 0.05);
            border: 1px solid rgba(0, 240, 255, 0.25);
            color: #00f0ff;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 10px 18px;
            border-radius: 25px;
            transition: all 0.25s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .cyber-link-btn:hover {
            background: #00f0ff;
            color: #000000;
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.5);
        }

        .cyber-panel {
            background: rgba(3, 8, 30, 0.75);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(0, 240, 255, 0.15);
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.7);
        }

        .panel-title-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: 1px;
            color: #00f0ff;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
            margin-bottom: 20px;
        }

        .cyber-input {
            background: rgba(1, 4, 15, 0.85);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 30px;
            color: #ffffff;
            font-size: 1rem;
            padding: 14px 24px;
            width: 100%;
            outline: none;
            transition: all 0.25s ease;
        }
        .cyber-input:focus {
            border-color: #00f0ff;
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.25);
        }

        .btn-glow-cyan {
            background: linear-gradient(135deg, #00f0ff 0%, #0072ff 100%);
            color: #000000;
            font-weight: 700;
            border-radius: 30px;
            font-size: 1.05rem;
            letter-spacing: 1px;
            box-shadow: 0 4px 20px rgba(0, 240, 255, 0.3);
            transition: all 0.3s ease;
        }
        .btn-glow-cyan:hover {
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.6);
            transform: scale(1.02);
        }

        .vector-card {
            background: linear-gradient(180deg, #05102a 0%, #01040f 100%);
            border: 1px solid rgba(0, 240, 255, 0.25);
            border-radius: 20px;
            padding: 16px;
        }

        .toast-container {
            position: fixed; top: 1rem; right: 1rem; z-index: 1000;
            display: flex; flex-direction: column; gap: 0.5rem;
        }
        .toast {
            background: rgba(3, 8, 30, 0.95); border: 1px solid rgba(0, 240, 255, 0.4); border-radius: 10px;
            padding: 0.8rem 1.2rem; font-size: 0.85rem; color: #ffffff;
            box-shadow: 0 8px 30px rgba(0,0,0,0.6); backdrop-filter: blur(12px);
        }
    </style>
</head>
<body class="py-6 px-4 max-w-xl mx-auto flex flex-col justify-start">

    <header class="flex flex-col items-center justify-center my-4 text-center">
        <div class="flex items-center gap-3">
            <h1 class="text-3xl font-extrabold tracking-wider uppercase font-sans bg-gradient-to-r from-cyan-400 to-blue-500 text-transparent bg-clip-text drop-shadow-lg neon-glow-cyan">
                FREXY ULTRA SPAM
            </h1>
            <a href="/logout" class="text-red-400 hover:text-red-500 text-sm ml-2" title="Logout">
                <i class="fa-solid fa-power-off"></i>
            </a>
        </div>
        <p class="text-xs font-semibold tracking-widest text-slate-400 uppercase mt-1 mb-5">
            Premium Cyber Infrastructure v3.0
        </p>
        
        <div class="flex flex-wrap items-center justify-center gap-3 mt-1 mb-2">
            {% if is_admin %}
            <!-- Admin-only User Manager Access Button at the Top -->
            <button onclick="toggleUserManager()" class="cyber-link-btn" style="border-color: #00f0ff; background: rgba(0, 240, 255, 0.15);">
                <i class="fa-solid fa-users-gear text-base text-cyan-400"></i> User Manager
            </button>
            {% endif %}
            <a href="https://t.me/jubayer_ahmed_34" target="_blank" class="cyber-link-btn">
                <i class="fa-solid fa-address-card text-base"></i> Developer Node
            </a>
        </div>
    </header>

    <!-- User Management Section (Admin Only) -->
    {% if is_admin %}
    <div id="userManagerPanel" class="cyber-panel mb-6 hidden">
        <div class="panel-title-bar">
            <i class="fa-solid fa-users-viewfinder text-cyan-400"></i>
            <h2>User Management Panel</h2>
        </div>
        <div class="space-y-4 mb-6">
            <h3 class="text-sm font-bold uppercase text-cyan-400">Add New Operator</h3>
            <div class="grid grid-cols-2 gap-2">
                <input type="text" id="newUsername" placeholder="Operator Username" class="bg-black/60 border border-cyan-500/20 px-3 py-2 rounded-xl text-xs text-white outline-none">
                <input type="password" id="newPassword" placeholder="Operator Password" class="bg-black/60 border border-cyan-500/20 px-3 py-2 rounded-xl text-xs text-white outline-none">
            </div>
            <button onclick="addUser()" class="w-full bg-cyan-500 text-black font-bold text-xs py-2.5 rounded-xl uppercase tracking-wider hover:opacity-90">
                Register Operator
            </button>
        </div>
        <div class="border-t border-cyan-500/10 pt-4">
            <h3 class="text-sm font-bold uppercase text-cyan-400 mb-3">Operator Cluster Registry</h3>
            <div id="dbUsersList" class="space-y-2 max-h-[150px] overflow-y-auto pr-1"></div>
        </div>
    </div>
    {% endif %}

    <div class="grid grid-cols-2 gap-4 mb-6">
        <div class="stat-box">
            <div class="stat-val" id="activeSpamCount">0</div>
            <div class="stat-lbl text-xs text-slate-400 uppercase tracking-widest mt-1">Active Vectors</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" id="accCount">0</div>
            <div class="stat-lbl text-xs text-slate-400 uppercase tracking-widest mt-1">Connected Bots</div>
        </div>
    </div>

    <div class="space-y-6">

        <div class="cyber-panel">
            <div class="panel-title-bar">
                <i class="fa-solid fa-crosshairs text-cyan-400"></i>
                <h2>FREXY CORE INTERACTION</h2>
            </div>
            
            <div class="space-y-4">
                <div class="flex items-center gap-2 relative w-full">
                    <input type="text" id="targetUid" class="cyber-input font-mono text-center tracking-widest flex-1" placeholder="Enter Target UID" inputmode="numeric">
                </div>
                
                <button id="startBtn" class="btn-glow-cyan w-full py-4 flex items-center justify-center gap-2 uppercase">
                    <i class="fa-solid fa-play text-xs"></i> Start Vector
                </button>
            </div>
            
            <div id="startMessage" class="hidden bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-xl p-3 mt-3 text-sm font-medium flex items-center gap-2"></div>
        </div>

        <div class="cyber-panel">
            <div class="panel-title-bar">
                <i class="fa-solid fa-satellite-dish text-cyan-400"></i>
                <h2>FREXY LIVE DATA LOGS</h2>
            </div>
            <div id="activeTargets" class="space-y-4">
                <div class="text-center text-sm text-gray-500 py-4 flex flex-col items-center justify-center gap-2">
                    <span class="flex items-center gap-2"><i class="fa-solid fa-mailbox opacity-40"></i> Empty vector queue</span>
                </div>
            </div>
        </div>

        <div class="cyber-panel">
            <div class="panel-title-bar">
                <i class="fa-solid fa-robot text-cyan-400"></i>
                <h2>CLUSTER NODES</h2>
            </div>
            <div class="space-y-2 max-h-[140px] overflow-y-auto" id="accountList">
                <div class="text-center text-sm text-gray-500 py-4">
                    <i class="fa-solid fa-circle-notch animate-spin text-xs text-cyan-400"></i> Syncing systems...
                </div>
            </div>
        </div>

    </div>

    <footer class="mt-8 mb-4 text-center text-[11px] font-semibold text-slate-500 tracking-widest uppercase">
        System Managed & Engineered By FREXY &copy; 2026
    </footer>

    <div class="toast-container" id="toast-container"></div>

    <script>
        window.activeSpamTimes = {};

        function showToast(message) {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => { toast.remove(); }, 3000);
        }

        function toggleUserManager() {
            const panel = document.getElementById('userManagerPanel');
            panel.classList.toggle('hidden');
            if(!panel.classList.contains('hidden')) {
                loadUsersList();
            }
        }

        function loadUsersList() {
            fetch('/admin/list_users')
                .then(res => res.json())
                .then(users => {
                    const listDiv = document.getElementById('dbUsersList');
                    listDiv.innerHTML = users.map(user => `
                        <div class="flex items-center justify-between bg-black/40 border border-cyan-500/10 px-4 py-2.5 rounded-xl text-xs font-mono">
                            <span class="text-slate-300">${user.username} ${user.is_admin ? '<span class="text-cyan-400 text-[10px] uppercase font-bold ml-1">[Admin]</span>':''}</span>
                            ${!user.is_admin ? `<button onclick="deleteUser('${user.username}')" class="text-red-400 hover:text-red-500"><i class="fa-solid fa-trash-can"></i></button>` : ''}
                        </div>
                    `).join('');
                });
        }

        function addUser() {
            const user = document.getElementById('newUsername').value.trim();
            const pass = document.getElementById('newPassword').value.trim();
            if(!user || !pass) {
                showToast("Please provide credentials!");
                return;
            }
            fetch('/admin/add_user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user, password: pass})
            })
            .then(res => res.json())
            .then(data => {
                if(data.error) showToast(data.error);
                else {
                    showToast("User registered successfully");
                    document.getElementById('newUsername').value = '';
                    document.getElementById('newPassword').value = '';
                    loadUsersList();
                }
            });
        }

        function deleteUser(username) {
            if(!confirm(`Confirm delete user: ${username}?`)) return;
            fetch(`/admin/delete_user?username=${encodeURIComponent(username)}`, {method: 'DELETE'})
                .then(res => res.json())
                .then(data => {
                    showToast(data.status || data.error);
                    loadUsersList();
                });
        }

        function triggerStopOperation(uid) {
            fetch(`/stop_spam?uid=${encodeURIComponent(uid)}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error) showToast(data.error);
                    else {
                        showToast(`Target Disconnected: ${data.status}`);
                        fetchStatus();
                    }
                });
        }

        function buildTargetCardMarkup(uid) {
            return `
                <div id="card-vector-${uid}" class="vector-card flex flex-col gap-3 relative overflow-hidden">
                    <div class="text-center font-mono text-xs border-b border-cyan-500/10 pb-2">
                        <span class="text-slate-400">TARGET UID:</span> <span class="text-cyan-400 font-bold">${uid}</span>
                    </div>
                    <div class="relative w-full rounded-xl border border-cyan-500/20 overflow-hidden bg-black/60">
                        <img src="https://nirob-free-fire-baner.vercel.app/profile?uid=${uid}" alt="Profile Banner" class="w-full h-auto min-h-[90px] object-cover" onerror="this.style.display='none'">
                    </div>
                    <div class="flex items-center justify-between mt-1">
                        <span class="bg-black/80 px-3 py-1.5 rounded-lg text-xs text-cyan-400 font-mono font-bold tracking-widest border border-cyan-500/20">
                            <i class="fa-solid fa-hourglass-start mr-1 text-xs"></i><span id="uptime-${uid}">0d 0h 0m</span>
                        </span>
                        <button onclick="triggerStopOperation('${uid}')" class="bg-red-600 hover:bg-red-700 text-white font-bold text-xs px-4 py-1.5 rounded-full uppercase tracking-wider font-mono">
                            <i class="fa-solid fa-power-off text-[10px] mr-1"></i> STOP
                        </button>
                    </div>
                </div>
            `;
        }

        function fetchStatus() {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('accCount').innerText = data.connected_accounts;
                    document.getElementById('activeSpamCount').innerText = data.active_spam.length;
                    
                    if (data.active_times) {
                        window.activeSpamTimes = data.active_times;
                    }
                    
                    const accListDiv = document.getElementById('accountList');
                    if (data.accounts && data.accounts.length) {
                        accListDiv.innerHTML = data.accounts.map(acc => `
                            <div class="text-xs bg-[#03091e] border border-cyan-500/20 px-4 py-3 rounded-xl text-slate-300 flex items-center justify-between">
                                <span class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_#00f0ff]"></span> FREXY_NODE</span>
                                <span class="text-cyan-300 font-mono font-medium">${acc}</span>
                            </div>
                        `).join('');
                    } else {
                        accListDiv.innerHTML = '<div class="text-slate-500 text-xs text-center py-3"><i class="fa-solid fa-robot opacity-40 mr-1.5"></i> No connection modules ready</div>';
                    }

                    const targetsDiv = document.getElementById('activeTargets');
                    if (data.active_spam && data.active_spam.length) {
                        const activeCards = targetsDiv.querySelectorAll('.vector-card');
                        activeCards.forEach(card => {
                            const cardId = card.id.replace('card-vector-', '');
                            if (!data.active_spam.includes(cardId)) {
                                card.remove();
                            }
                        });

                        if (targetsDiv.innerHTML.includes('Empty vector queue')) {
                            targetsDiv.innerHTML = '';
                        }

                        data.active_spam.forEach(uid => {
                            if (!document.getElementById(`card-vector-${uid}`)) {
                                targetsDiv.insertAdjacentHTML('beforeend', buildTargetCardMarkup(uid));
                            }
                        });
                    } else {
                        targetsDiv.innerHTML = '<div class="text-slate-500 text-sm text-center py-4 flex flex-col items-center justify-center gap-2"><span><i class="fa-solid fa-satellite-dish opacity-40"></i> Empty vector queue</span></div>';
                    }
                })
                .catch(err => console.error(err));
        }

        document.getElementById('startBtn').onclick = () => {
            const uid = document.getElementById('targetUid').value.trim();
            if (!uid) {
                showToast('Please type a target UID!');
                return;
            }
            if (!/^\d+$/.test(uid)) {
                showToast('UID must contain only numbers!');
                return;
            }
            
            fetch(`/start_spam?uid=${encodeURIComponent(uid)}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        showToast(data.error);
                    } else {
                        showToast("Vector Cluster Deployed Successfully");
                        document.getElementById('targetUid').value = '';
                        fetchStatus();
                    }
                });
        };

        setInterval(() => {
            for (const uid in window.activeSpamTimes) {
                const el = document.getElementById(`uptime-${uid}`);
                if (el) {
                    const startTime = window.activeSpamTimes[uid];
                    const now = Math.floor(Date.now() / 1000);
                    let diff = now - startTime;
                    if (diff < 0) diff = 0;
                    
                    const d = Math.floor(diff / 86400);
                    const h = Math.floor((diff % 86400) / 3600);
                    const m = Math.floor((diff % 3600) / 60);
                    
                    el.innerText = `${d}d ${h}h ${m}m`;
                }
            }
        }, 1000);

        fetchStatus();
        setInterval(fetchStatus, 3000);
    </script>
</body>
</html>
'''

# ---------- Flask Routes ----------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password, is_admin FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0] == password:
            session['username'] = username
            session['is_admin'] = bool(row[1])
            return redirect(url_for('index'))
        else:
            error = "Authentication failed. Invalid username or password."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE, is_admin=session.get('is_admin', False))

@app.route('/api/status')
@login_required
def api_status():
    username = session.get('username')
    with active_spam_lock:
        # Get only target queue belonging to the currently logged in user
        user_targets = active_spam_targets.get(username, {})
        active = list(user_targets.keys())
        active_times = {
            uid: (user_targets[uid] if isinstance(user_targets[uid], float) else datetime.now().timestamp()) 
            for uid in user_targets
        }
    return jsonify({
        'connected_accounts': len(connected_clients),
        'accounts': list(connected_clients.keys()),
        'active_spam': active,
        'active_times': active_times 
    })

@app.route('/start_spam')
@login_required
def start_spam_route():
    target = request.args.get('uid')
    duration = request.args.get('duration', type=int)
    username = session.get('username')
    if not target:
        return jsonify({'error': 'uid configuration parameter required'}), 400
    if not connected_clients:
        return jsonify({'error': 'No bot interfaces currently configured online'}), 500
    
    with active_spam_lock:
        if username not in active_spam_targets:
            active_spam_targets[username] = {}
        if target in active_spam_targets[username]:
            return jsonify({'error': f'{target} is already actively being processed'}), 409
        
        active_spam_targets[username][target] = datetime.now().timestamp()
        threading.Thread(target=spam_worker, args=(target, duration, username), daemon=True).start()
        
    return jsonify({
        'status': 'Vector successfully started',
        'target': target,
        'duration_minutes': duration
    })

@app.route('/stop_spam')
@login_required
def stop_spam_route():
    target = request.args.get('uid')
    username = session.get('username')
    if not target:
        return jsonify({'error': 'uid configuration parameter required'}), 400
    
    with active_spam_lock:
        if username in active_spam_targets and target in active_spam_targets[username]:
            del active_spam_targets[username][target]
            return jsonify({'status': f'Vector operation targeting {target} terminated'})
        else:
            return jsonify({'error': f'No current vector process exists for {target}'}), 404

# ---------- Admin Only DB Routes ----------

@app.route('/admin/list_users')
@login_required
def admin_list_users():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_admin FROM users")
    users = [{'username': r[0], 'is_admin': bool(r[1])} for r in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def admin_add_user():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Invalid arguments'}), 400
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, password))
        conn.commit()
        conn.close()
        return jsonify({'status': 'Success'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/admin/delete_user', methods=['DELETE'])
@login_required
def admin_delete_user():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.args.get('username')
    if not username or username == 'frexy':
        return jsonify({'error': 'Cannot delete master account'}), 400
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({'status': f'User {username} deleted successfully'})


if __name__ == '__main__':
    # Background worker thread configuration
    threading.Thread(target=start_all_accounts, daemon=True).start()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

from gevent import monkey
monkey.patch_all()

from gevent import monkey; monkey.patch_all()
import os, json, sqlite3, threading, logging, gevent
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from steam.client import SteamClient

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Substitua por uma chave segura
DATABASE = os.path.join(os.path.dirname(__file__), "app.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                steam_username TEXT NOT NULL,
                steam_password TEXT NOT NULL,
                games TEXT NOT NULL,
                sentry BLOB,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        conn.commit()
    logging.info("Banco de dados inicializado.")

init_db()

# Dicionários globais para manter o estado
clients_waiting_2fa = {}  # account_id -> { ... }
running_clients = {}      # account_id -> client
paused_status = {}        # account_id -> Boolean (True se o farm estiver pausado)
clients_lock = threading.Lock()

# Funções auxiliares para persistir a sessão
def load_saved_session(account_id):
    session_file = f"session_{account_id}.json"
    if os.path.exists(session_file):
        try:
            with open(session_file, "r") as f:
                session_data = json.load(f)
            return session_data
        except Exception as e:
            logging.error("Erro ao carregar a sessão: %s", e)
    return None

def save_session_data(account_id, session_data):
    session_file = f"session_{account_id}.json"
    try:
        with open(session_file, "w") as f:
            json.dump(session_data, f)
        logging.info("Sessão salva com sucesso para a conta %s.", account_id)
    except Exception as e:
        logging.error("Erro ao salvar sessão: %s", e)

def handle_account(account_id, account, user_id):
    """
    Efetua login na conta Steam e inicia um loop que envia periodicamente o status dos games,
    a menos que a conta esteja em modo "pausado".
    """
    client = SteamClient()
    state = {"awaiting_2fa": False}

    # Tenta carregar o sentry salvo no BD (se existir)
    sentry_data = None
    with get_db() as conn:
        cur = conn.execute("SELECT sentry FROM accounts WHERE id = ?", (account_id,))
        row = cur.fetchone()
        if row and row["sentry"]:
            sentry_data = row["sentry"]

    if sentry_data:
        try:
            client.load_sentry(sentry_data)
            logging.info(f"[✓] Sessão carregada para {account['steam_username']} usando sentry do BD.")
        except Exception as e:
            logging.error(f"Falha ao carregar sentry: {e}")
            sentry_data = None

    def on_auth_code_required(is_2fa, code_mismatch, acc_id=account_id, username=account["steam_username"]):
        with clients_lock:
            entry = clients_waiting_2fa.get(int(acc_id))
            if entry and entry.get("two_factor_attempted", False):
                logging.info(f"[~] Callback 2FA ignorado para {username}, já foi tentado.")
                return
            state["awaiting_2fa"] = True
            clients_waiting_2fa[int(acc_id)] = {
                "account_id": int(acc_id),
                "client": client,
                "steam_username": username,
                "steam_password": account["steam_password"],
                "two_factor_attempted": False,
                "auth_callback": on_auth_code_required
            }
        logging.info(f"[+] Aguardando 2FA para {username}")

    @client.on("auth_code_required")
    def auth_code_required_wrapper(*args, **kwargs):
        on_auth_code_required(*args, **kwargs)

    @client.on("logged_on")
    def on_logged_on():
        with clients_lock:
            running_clients[int(account_id)] = client
            if int(account_id) in clients_waiting_2fa:
                del clients_waiting_2fa[int(account_id)]
        logging.info(f"[✓] {account['steam_username']} conectado.")
        # Após login, salva o sentry atualizado
        try:
            new_sentry = client.get_sentry(account["steam_username"])  # Ajuste conforme a API
            with get_db() as conn:
                conn.execute("UPDATE accounts SET sentry = ? WHERE id = ?", (new_sentry, account_id))
                conn.commit()
            logging.info(f"[✓] Sentry salvo para {account['steam_username']}.")
        except Exception as e:
            logging.error("Erro ao obter e salvar o sentry: %s", e)

    # Função que executa o "farm" de jogos periodicamente
    def farm_loop():
        while True:
            # Se a conta não estiver pausada, envia o status dos games
            if not paused_status.get(account_id, False):
                try:
                    games = json.loads(account["games"])
                    client.games_played(games)
                    logging.info(f"[✓] {account['steam_username']} enviando status de jogos {games}.")
                except Exception as e:
                    logging.error("Erro em games_played: %s", e)
            else:
                # Se estiver pausada, pode enviar uma lista vazia para "limpar" o status ou simplesmente aguardar
                try:
                    client.games_played([])  # Opcional: limpar o status de jogo
                    logging.info(f"[!] {account['steam_username']} em modo ocioso (pausado).")
                except Exception as e:
                    logging.error("Erro ao limpar status de jogos: %s", e)
            gevent.sleep(60)  # Aguarda 60 segundos antes de repetir

    # Inicia o loop de farm em background (modo ocioso ou ativo conforme flag)
    gevent.spawn(farm_loop)

    logging.info(f"[+] Tentando login: {account['steam_username']}")
    if sentry_data:
        client.login(account["steam_username"], account["steam_password"], sentry=sentry_data)
    else:
        client.login(account["steam_username"], account["steam_password"])
    client.run_forever()


# Rotas de autenticação
@app.route("/login", methods=["GET", "POST"])
def login_route():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        with get_db() as conn:
            cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            if user and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("index_route"))
            else:
                flash("Usuário ou senha incorretos")
    return render_template("login.html")

@app.route("/logout")
def logout_route():
    session.clear()
    return redirect(url_for("login_route"))

def get_user_accounts(user_id):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,))
        accounts = cur.fetchall()
    return accounts

# Página principal: exibe contas, status, formulário de 2FA, edição, etc.
@app.route("/")
def index_route():
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    accounts = get_user_accounts(session["user_id"])
    with clients_lock:
        running_status = list(running_clients.keys())
        waiting_2fa = list(clients_waiting_2fa.keys())
    return render_template("index.html", accounts=accounts, username=session.get("username"),
                           running_status=running_status, waiting_2fa=waiting_2fa)

# Rota para adicionar nova conta
@app.route("/add_account", methods=["POST"])
def add_account_route():
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    steam_username = request.form["steam_username"]
    steam_password = request.form["steam_password"]
    games_str = request.form.get("games", "")
    try:
        games_list = [int(g.strip()) for g in games_str.split(",") if g.strip().isdigit()]
    except Exception as e:
        flash("Formato inválido para games IDs.")
        return redirect(url_for("index_route"))
    games_json = json.dumps(games_list)
    user_id = session["user_id"]
    with get_db() as conn:
        conn.execute(
            "INSERT INTO accounts (user_id, steam_username, steam_password, games) VALUES (?, ?, ?, ?)",
            (user_id, steam_username, steam_password, games_json)
        )
        conn.commit()
    flash("Conta adicionada com sucesso.")
    return redirect(url_for("index_route"))

# Rota para remover conta
@app.route("/remove_account/<int:account_id>", methods=["POST"])
def remove_account_route(account_id):
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    user_id = session["user_id"]
    with get_db() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ? AND user_id = ?", (account_id, user_id))
        conn.commit()
    flash("Conta removida.")
    return redirect(url_for("index_route"))

# Rota para atualizar os games IDs de uma conta
@app.route("/update_games/<int:account_id>", methods=["POST"])
def update_games_route(account_id):
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    games_str = request.form.get("games", "")
    try:
        games_list = [int(g.strip()) for g in games_str.split(",") if g.strip().isdigit()]
    except Exception as e:
        flash("Formato inválido para games IDs.")
        return redirect(url_for("index_route"))
    games_json = json.dumps(games_list)
    with get_db() as conn:
        conn.execute("UPDATE accounts SET games = ? WHERE id = ? AND user_id = ?",
                     (games_json, account_id, session["user_id"]))
        conn.commit()
    flash("Games IDs atualizados.")
    return redirect(url_for("index_route"))

# Rota para ativar/desativar uma conta
@app.route("/toggle/<int:account_id>", methods=["POST"])
def toggle_route(account_id):
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    with clients_lock:
        if account_id in running_clients:
            # Alterna o status: se estiver ativo, pausa; se estiver pausado, reativa
            current = paused_status.get(account_id, False)
            paused_status[account_id] = not current
            if paused_status[account_id]:
                flash(f"Conta {account_id} pausada (modo ocioso).")
                logging.info(f"Conta {account_id} pausada.")
            else:
                flash(f"Conta {account_id} reativada (farm ativo).")
                logging.info(f"Conta {account_id} reativada.")
        else:
            # Se a conta não estiver rodando, inicia-a
            accounts = get_user_accounts(session["user_id"])
            account = next((a for a in accounts if int(a["id"]) == account_id), None)
            if account is None:
                flash("Conta não encontrada.")
                return redirect(url_for("index_route"))
            # Inicia a conta (modo ativo por padrão)
            paused_status[account_id] = False
            threading.Thread(
                target=handle_account,
                args=(account_id, account, session["user_id"]),
                daemon=True
            ).start()
            flash(f"Ativando conta {account_id}...")
    return redirect(url_for("index_route"))

# Rota para submeter o código 2FA para uma conta específica
@app.route("/submit_2fa/<int:account_id>", methods=["POST"])
def submit_2fa_route(account_id):
    if "user_id" not in session:
        return redirect(url_for("login_route"))
    auth_code = request.form.get("auth_code")
    if not auth_code:
        flash("Código 2FA não informado.")
        return redirect(url_for("index_route"))
    with clients_lock:
        if account_id in clients_waiting_2fa:
            data = clients_waiting_2fa[account_id]
            client = data["client"]
            username = data["steam_username"]
            password = data["steam_password"]
            data["two_factor_attempted"] = True
            try:
                client.remove_listener("auth_code_required", data["auth_callback"])
            except Exception as e:
                logging.warning("Não foi possível remover o listener (pode ser inofensivo): %s", e)

        else:
            flash("Conta não aguardando 2FA ou já processada.")
            return redirect(url_for("index_route"))
    gevent.spawn(client.login, username, password, two_factor_code=auth_code)
    flash(f"Código 2FA enviado para a conta {account_id}.")
    return redirect(url_for("index_route"))

@app.route("/status_2fa")
def status_2fa():
    with clients_lock:
        waiting = list(clients_waiting_2fa.keys())
    # Retorna algo como: {"waiting_2fa": [1, 3, 5]}
    return {"waiting_2fa": waiting}

if __name__ == "__main__":
    app.run(debug=False)

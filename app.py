import os, sys, joblib, argparse
from pathlib import Path
from flask import Flask, request, session, jsonify, render_template, redirect, url_for
from werkzeug.serving import WSGIRequestHandler
from dotenv import load_dotenv

from honeypot.deception import deception_sqli, deception_xss, deception_rce, deception_lfi
from honeypot.logger import ip_tracker, threat_level, log_request
from ml.features import extract_features

# -----------------------
# Parsing de argumentos
# -----------------------

parser = argparse.ArgumentParser(description = "WebTrap - Honeypot Web Adaptativo")

parser.add_argument(
    "-e", "--expose", 
    action="store_true", 
    help="Exposição para 0.0.0.0 (PERMITE ACESSO EXTERNO)"
)

parser.add_argument(
    "-p","--port",
    type=int,
    default=5000,
    help="Alterna a porta utilizada"
)

parser.add_argument(
    "--debug",
    action="store_true",
    help="Ativa o modo debug - marca quantidade de req. benignas e malignas"
)

parser.add_argument(
    "-n", "--numeric",
    action="store_true",
    help="SOMENTE COM DEBUG: Testa modelo SOMENTE com features numéricas (ver README)"
)

parser.add_argument(
    "-t", "--tfidf",
    action="store_true",
    help="SOMENTE COM DEBUG: Testa modelo SOMENTE com features textuais (tf-idf) (ver README)"
)

args = parser.parse_args()

# -----------------------
# Ajuste de Flags
# -----------------------

HOST_IP = "0.0.0.0" if args.expose else "127.0.0.1"
HOST_PORT = args.port

DEBUG = args.debug

# Para testar outros modelos sem features combinadas, ative o DEBUG
if (not DEBUG) and (args.numeric or args.tfidf):
    print("ALERTA: Para testar modelos sem features combinadas ative o modo DEBUG.")
    exit(1)

# Se usar as duas flags ao mesmo tempo
if (args.numeric and args.tfidf):
    print("ALERTA: Para testar o modelo com ambas features numéricas e textuais não use flag -n e -t.")
    exit(1)

if(args.numeric):  FEATURE = "NUM"
elif (args.tfidf): FEATURE = "TFI"
else:              FEATURE = "BTH"

# Variáveis para Debug e Testes
total_requests = 0
total_benign = 0
total_malign = 0

# ------------------------------------------------------------------
# Obtendo Diretórios e carregando Modelos de Aprendizado de Máquina
# ------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

REQUEST_DIR = BASE_DIR / "ml" / "request_model"
ATTACK_DIR  = BASE_DIR / "ml" / "attack_model"

request_model          = joblib.load(REQUEST_DIR / "model.pkl")
request_vectorizer     = joblib.load(REQUEST_DIR / "vectorizer.pkl")
request_scaler         = joblib.load(REQUEST_DIR / "scaler.pkl")
request_method_encoder = joblib.load(REQUEST_DIR / "method_encoder.pkl")
request_model.verbose  = 0

attack_model          = joblib.load(ATTACK_DIR / "model.pkl")
attack_vectorizer     = joblib.load(ATTACK_DIR / "vectorizer.pkl")
attack_scaler         = joblib.load(ATTACK_DIR / "scaler.pkl")
attack_method_encoder = joblib.load(ATTACK_DIR / "method_encoder.pkl")
attack_model.verbose  = 0


# --------------------------------
# Configuração do Servidor Flask
# --------------------------------


load_dotenv()

app = Flask(__name__,
            template_folder=str(BASE_DIR / "honeypot" / "templates"),
            static_folder=str(BASE_DIR / "honeypot" / "static"))
app.secret_key = os.environ.get("SECRET_KEY", "change-me-before-production")

class PortAwareHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        environ["REMOTE_PORT"] = str(self.client_address[1])
        return environ

    
# ---------------------------------------
# Classificação de Requisições e Ataques
# ---------------------------------------

# Extração de features e predição
def classify(req, model, vectorizer, scaler, encoder, default=None):

    # Dependendo do método, pegará informações de uma parte específica da requisição
    payload = (req.query_string.decode() if req.method == "GET"
               else req.get_data(as_text=True))

    if not payload:
        return default

    # Mesmas features para os dois modelos
    features = extract_features(req.method, payload, vectorizer, scaler, encoder, FEATURE)

    return model.predict(features)[0]


# Classificador de Requisições
def ml_prediction(req) -> int:
    result = classify(req, request_model, request_vectorizer,
                      request_scaler, request_method_encoder, default=0)
    return result.item() if hasattr(result, "item") else result

# Classificador de Ataques
def identify_attack(req) -> int:
    result = classify(req, attack_model, attack_vectorizer,
                      attack_scaler, attack_method_encoder, default=0)
    return result.item() if hasattr(result, "item") else result


# ---------------------------------------
# Lógica de Decisão
# ---------------------------------------

ATTACK_DECISIONS = {
    "sqli": "sql_error",
    "xss":  "xss_error",
    "lfi":  "lfi_error",
    "rce":  "rce_output",
}


# Envia as requisições as funções que lidam com classificação, dependendo do tipo
def base_decision(req) -> tuple[str, str, str]:
    
    prediction = ml_prediction(req)

    # Feito para aceitar Random Forest e XGBoost

    if (prediction == "Valid" or prediction == 0):
        return prediction, "none", "normal"
    else:
        prediction = "Anomalous"


    attack_type = str.lower(identify_attack(req))

    match(attack_type):
        case 0:
            attack_type = "sqli"
        case 1:
            attack_type = "xss"
        case 2:
            attack_type = "rce"
        case 4:
            attack_type = "lfi"

    ip_tracker(req.remote_addr, attack_type)

    # Ataques não reconhecidos recebem resposta genérica de erro de servidor - redundância a erros
    decision = ATTACK_DECISIONS.get(attack_type, "server_error")
    return prediction, attack_type, decision


# Análise de requisição
def request_analysis(directory: str, req) -> tuple[str, str]:
    
    match directory:
        case "search" | "login":
            prediction, attack_type, decision = base_decision(req)
        case _:
            prediction, attack_type, decision = "null", "none", "normal"

    if(DEBUG):
        debug_requests(prediction)

    log_request(prediction, attack_type, decision)
    return decision, attack_type


# Auxiliar para identificar quantidade de requisições foram marcadas como benignas ou malignas
def debug_requests(prediction: str):
    global total_requests, total_benign, total_malign
    total_requests += 1

    if(prediction in ("null", "none", "normal", "Valid")):
        total_benign += 1
    else:
        total_malign += 1

    print(f" [DEBUG] > Total Req. = {total_requests} ,"
          f"Total Ben. = {total_benign} ,"
          f"Total Mal. = {total_malign}  ")

    return

# ---------------------------------------
# Header de Deception
# ---------------------------------------


@app.after_request
def add_headers(response):
    response.headers["Server"]       = "Apache/2.4.49"
    response.headers["X-Powered-By"] = "PHP/7.4"
    return response


# ---------------------------------------
# Rotas Principais
# ---------------------------------------

@app.route("/")
def home():
    return render_template("index.html")

# Envia requisições para análise
@app.route("/search")
def search():
    decision, attack_type = request_analysis("search", request)
    query       = request.args.get("q", "")
    ip          = request.remote_addr
    level       = threat_level(ip)

    match decision:
        case "normal":       
            return render_template("search.html", query=query)

        case "sql_error":
            content, status = deception_sqli(level, "search")
            return render_template("search.html", query=query, error=content), status

        case "xss_error":    return deception_xss(query, level)
        case "lfi_error":    return deception_lfi(level)
        case "rce_output":   return deception_rce(level)
        case "server_error": return "Internal Server Error", 500

    return render_template("search.html", query=query)


@app.route("/admin")
def admin():
    return redirect(url_for("login"))


# Envia requisições para análise
@app.route("/login", methods=["GET", "POST"])
def login():
    decision, attack_type = request_analysis("login", request)
    payload     = (request.form.get("username", "")
                   + " " + request.form.get("password", ""))
    ip          = request.remote_addr
    level       = threat_level(ip)

    match decision:
        case "normal":
            if request.method == "POST":
                    return render_template("login.html", error="Usuário ou senha incorretos."), 401
            return render_template("login.html")

        case "sql_error":
            content, status = deception_sqli(level, "login")
            return render_template("login.html", error=content), status

        case "xss_error":    return deception_xss(payload, level)
        case "lfi_error":    return deception_lfi(level)
        case "rce_output":   return deception_rce(level)
        case "server_error": return "Internal Server Error", 500

    return render_template("login.html")


@app.route("/login/admin")
def login_admin():
    if not session.get("logged"):
        return redirect(url_for("login"))
    return render_template("admin.html")


# ---------------------------------------
# Rotas Extras para Scanner
# ---------------------------------------

@app.route("/.git/config")
def git_config():
    return (
        "[core]\n\trepositoryformatversion = 0\n"
        "\tfilemode = true\n\tbare = false\n"
        "[remote \"origin\"]\n\turl = git@github.com:govbr/portal-interno.git\n"
        "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
    )

@app.route("/config.php")
def config():
    return (
        "<?php\n"
        "$db_host = 'localhost';\n"
        "$db_user = 'portal_user';\n"
        "$db_pass = 's3cr3t_p4ss';\n"
        "$db_name = 'portal_db';\n"
        "?>"
    )

@app.route("/phpmyadmin")
def phpmyadmin():
    return render_template("login.html")

@app.route("/wp-login.php")
def wp_login():
    return render_template("login.html")

@app.route("/xmlrpc.php")
def xmlrpc():
    return "XML-RPC server accepts POST requests only.", 405

@app.route("/.env")
def env():
    return (
        "APP_NAME=PortalServicos\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=127.0.0.1\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=portal_db\n"
        "DB_USERNAME=portal_user\n"
        "DB_PASSWORD=s3cr3t_p4ss\n"
    )

@app.route("/api/login", methods=["POST"])
def api_login():
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ---------------------------------------
# Inicialização do Servidor Flask
# ---------------------------------------

if __name__ == "__main__":
    app.run(host=HOST_IP, port=HOST_PORT, debug=DEBUG,
            request_handler=PortAwareHandler)
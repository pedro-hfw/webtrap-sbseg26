import argparse
import random
import requests
from faker import Faker

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
    "-H", "--host", 
    type=str,
    default="127.0.0.1",
    help="Alterna IP alvo (padrão 127.0.0.1)"
)

parser.add_argument(
    "-p", "--port",
    type=int,
    default=5000,
    help="Alterna a porta utilizada (padrão 5000)"
)

parser.add_argument(
    "-r","--repeats",
    type=int,
    default=500,
    help="Quantidade de requisições enviadas (padrão 500)"
)

args = parser.parse_args()

# -----------------------------------------------------
# Configuração
# -----------------------------------------------------

HOST_IP = args.host
HOST_PORT = args.port
SPECIAL = args.special
REPEATS = args.repeats

HOST    = f"http://{HOST_IP}:{HOST_PORT}"

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

# -----------------------------------------------------------------------
# Detecção de Deception: analisa se a requisição foi considerada anômala
# Verifica se as palavras a seguir apareceram na resposta
# -----------------------------------------------------------------------

_SQLI_MARKERS = [
    "mysqli_fetch_assoc",
    "sqlstate[",
    "fatal error: uncaught mysqli",
    "portal_db",
    "password_hash",
    "rows returned from",
]

_XSS_MARKERS = [
    "painel administrativo — notificações",
    "log de auditoria do sistema",
    "ticket de suporte #",
    "mural de mensagens — acesso restrito",
    "perfil do usuário",
    "comunicados internos",
]

_RCE_MARKERS = [
    "uid=33(www-data)",
    "portal-srv-prod-01",
    "usr/sbin/apache2",
    "mysqld",
    "crontab -l",
]

_LFI_MARKERS = [
    "root:x:0:0:root",
    "www-data:x:33:33",
    "/bin/bash",
    "portal:x:1001",
    "sha-512",
    "authorized_keys",
    "s3cr3t_p4ss",
]

_ALL_DECEPTION_MARKERS = _SQLI_MARKERS + _XSS_MARKERS + _RCE_MARKERS + _LFI_MARKERS

# Verifica se ativou o Deception, se sim retorna true
def _is_deception(resp) -> bool:
    if resp.status_code in (500, 504):
        return True
    if resp.elapsed.total_seconds() > 2.5:
        return True
    body = resp.text.lower()
    return any(marker in body for marker in _ALL_DECEPTION_MARKERS)

# -----------------------------------------------------
# Teste principal:
# -----------------------------------------------------

# 1 - Envia requisições geradas ao WebTrap
# 2 - Verifica se ativou o deception
# 3 - Registra e retorna a quantidade de falsos positivos
def test_false_positives(n: int = REPEATS) -> float:
    results = {"normal": 0, "false_positive": 0, "error": 0}
    fps: list[dict] = []

    print(f"\nTestando {n} requisições benignas contra {HOST}...\n")

    for _ in range(n):
        method, path, params = generate_request()

        try:
            if method == "GET":
                resp = requests.get(HOST + path, params=params, timeout=10)
            else:
                resp = requests.post(HOST + path, data=params, timeout=10)

            # Se identificar Deception salva a requisição em "fps"
            if _is_deception(resp):
                results["false_positive"] += 1
                fps.append({
                    "method": method,
                    "path":   path,
                    "params": params,
                    "status": resp.status_code,
                    "time":  f"{resp.elapsed.total_seconds():.2f}s",
                    "marker": next(
                        (m for m in _ALL_DECEPTION_MARKERS if m in resp.text.lower()),
                        "status/timeout",
                    ),
                })
            else:
                results["normal"] += 1

        # Possível timeout considera falso positivo
        except requests.exceptions.Timeout:
            results["false_positive"] += 1
            fps.append({
                "method": method, "path": path, "params": params,
                "status": "TIMEOUT", "time": ">10s", "marker": "timeout",
            })
        # Erro para qualquer problema ocorrido
        except Exception:
            results["error"] += 1

    valid_total = results["normal"] + results["false_positive"]
    fp_rate = results["false_positive"] / valid_total * 100 if valid_total else 0

    print("------------------------------------------------------------")
    print(f"  Total enviadas         :  {n}")
    print(f"  Classificadas normal   :  {results['normal']}")
    print(f"  Falso positivos        :  {results['false_positive']}")
    print(f"  Taxa de falso positivo :  {fp_rate:.1f}%")
    print(f"  Erros de conexão       :  {results['error']}")
    print("------------------------------------------------------------")

    # Printa 20 casos de falso positivos
    if fps:
        print(f"\n  Casos classificados como ataque ({min(len(fps), 20)} de {len(fps)}):\n")
        for f in fps[:20]:
            print(
                f"  [{f['method']}] {f['path']} | {f['params']}\n"
                f"      → status {f['status']} ({f['time']}) | marker: {f['marker']!r}\n"
            )

    return fp_rate


if __name__ == "__main__":

    test_false_positives(REPEATS)
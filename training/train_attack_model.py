import re, joblib, sys, argparse, pandas as pd
from pathlib import Path
from scipy.sparse import csr_matrix, hstack
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from urllib.parse import unquote
from attack_keywords import *

# Resumo: Treino de modelos de classificação

# -----------------------
# Parsing de argumentos
# -----------------------

parser = argparse.ArgumentParser(description = "Treino de modelos de classificação de tipo" \
                                "de ataque web")

parser.add_argument(
    "-a", "--algorithm",
    type=str,
    default="null",
    help="Escolha do algoritmo para treinamento, como '-a RF' ou '-a XGB'"
)

args = parser.parse_args()

# -----------------------
# Ajuste de Flags
# -----------------------

ALGORITHM = args.algorithm

if ALGORITHM not in ("RF", "XGB"): 

    print("\nFlag de algoritmo não utilizada, usando valor padrão: Random Forest.\n" \
    "Use a flag --help ou veja o README para auxílio.")

    ALGORITHM = "RF"

# -----------------------------------------------------
# Diretórios
# -----------------------------------------------------


SCRIPT_DIR   = Path(__file__).resolve().parent
DATASET_PATH = SCRIPT_DIR / "datasets" / "dataset_attack_classifier.csv"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

if not DATASET_PATH.exists():
    raise FileNotFoundError(f"Dataset não encontrado: {DATASET_PATH}")

MODEL_PATH = SCRIPT_DIR / 'attack_model_versions'
MODEL_PATH.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------
# Carregamento de Dataset
# -----------------------------------------------------


df = pd.read_csv(
    DATASET_PATH,
    sep="«",
    engine="python",
    encoding="utf-8",
)

df.dropna(subset=["Request", "Method", "Class"], inplace=True)
df.reset_index(drop=True, inplace=True)

# Criação de duas colunas: codificada e descodificada
df["Request_decoded"] = df["Request"].apply(lambda x: unquote(unquote(str(x))).lower())


# -----------------------------------------------------
# Features Numéricas
# -----------------------------------------------------


print("Criando features numéricas...")

# Features gerais de requisição

df["req_length"]      = df["Request"].str.len()
df["num_encoded"]     = df["Request"].str.count(r"%[0-9a-fA-F]{2}")
df["num_params"]      = df["Request_decoded"].str.count("=")
df["num_plus"]        = df["Request_decoded"].str.count(r"\+")
df["num_quotes"]      = df["Request_decoded"].str.count("'")
df["num_special_chars"]= df["Request_decoded"].str.count(r'[<>;"\\]')

df["num_traversal"]   = (
    df["Request"].str.count(r"\.\./")           
  + df["Request"].str.count(r"\.\.\\")          
)

# Features específicas de ataques

df["num_sqlwords"] = 0
for word in SQL_KEYWORDS:
    df["num_sqlwords"] += df["Request_decoded"].str.lower().str.count(re.escape(word))

df["num_sql_comments"] = (
    df["Request_decoded"].str.count(r"--")
  + df["Request_decoded"].str.count(r"/\*.*?\*/")
)

df["num_xsswords"] = 0
for word in XSS_KEYWORDS:
    df["num_xsswords"] += df["Request_decoded"].str.lower().str.count(re.escape(word))

df["num_shell_ops"] = 0
for op in RCE_SHELL_OPS:
    df["num_shell_ops"] += df["Request_decoded"].str.lower().str.count(re.escape(op))

df["num_rcefuncs"] = 0
for fn in RCE_FUNCTIONS:
    df["num_rcefuncs"] += df["Request_decoded"].str.lower().str.count(re.escape(fn))

df["num_shell_cmds"] = 0
for word in RCE_SHELL_COMMANDS:
    df["num_shell_cmds"] += df["Request_decoded"].str.lower().str.count(re.escape(word))


# -----------------------------------------------------
# Features Textuais (TF-IDF)
# -----------------------------------------------------


print("Preparando features textuais (TF-IDF)...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=1500,      
    min_df=3,               
    max_df=0.85,
    sublinear_tf=True,      
)

# Utiliza requisições codificadas (originais) para o TF-IDF
X_tfidf = vectorizer.fit_transform(df["Request"])


# -----------------------------------------------------
# Normalização de Features Numéricas
# -----------------------------------------------------


print("Normalizando features numéricas...")

numeric_features = [
    "req_length",
    "num_params",
    "num_plus",
    "num_quotes",
    "num_special_chars",
    "num_encoded",
    "num_traversal",        
    "num_sqlwords",
    "num_sql_comments",     
    "num_xsswords",
    "num_shell_ops",        
    "num_rcefuncs",         
    "num_shell_cmds",                    
]

scaler = StandardScaler()
X_numeric_scaled  = scaler.fit_transform(df[numeric_features].values)
X_numeric_sparse  = csr_matrix(X_numeric_scaled)


# -----------------------------------------------------
# ONE-HOT Encoding do Método HTTP
# -----------------------------------------------------


print("Codificando Method (one-hot)...")

method_encoder = OneHotEncoder(sparse_output=True, handle_unknown="ignore")
X_method = method_encoder.fit_transform(df[["Method"]])
method_feature_names = list(method_encoder.get_feature_names_out(["Method"]))


# -----------------------------------------------------
# Montagem da Matriz Final
# -----------------------------------------------------


X = hstack([X_tfidf, X_numeric_sparse, X_method])

# Mapeia classes para números (característica do XGB)
if(ALGORITHM == 'XGB'):

    Y = df["Class"].map({'SQLI':0 , 'XSS':1 , 'RCE':2 , 'LFI':3})

    model = XGBClassifier(
        n_estimators=200,      
        max_depth=20,   
        learning_rate=0.1,
        random_state=42,       
    )

if(ALGORITHM == 'RF'):

    Y = df["Class"]

    model = RandomForestClassifier(
        n_estimators=200,       
        max_depth=20,
        min_samples_leaf=2,     
        class_weight="balanced",
        random_state=42,
        verbose=1,
    )


# -----------------------------------------------------
# Treinamento
# -----------------------------------------------------


print("Dividindo dataset e treinando...")

X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y,
    test_size=0.2,
    random_state=42,
    stratify=Y,    
)

if(sys.argv[1] == 'XGB'):
    model = XGBClassifier(
        n_estimators=200,      
        max_depth=20,   
        learning_rate=0.1,
        random_state=42,       
    )

if(sys.argv[1] == 'RF'):
    model = RandomForestClassifier(
    n_estimators=200,       
    max_depth=20,
    min_samples_leaf=2,     
    class_weight="balanced",
    random_state=42,
    verbose=1,
)

model.fit(X_train, Y_train)


# -----------------------------------------------------
# Avaliação
# -----------------------------------------------------


Y_pred = model.predict(X_test)

print(f"\nAcurácia: {accuracy_score(Y_test, Y_pred):.4f}")
print(classification_report(Y_test, Y_pred, digits=6))


# -----------------------------------------------------
# Salvamento dos Artefatos
# -----------------------------------------------------


print("Salvando artefatos...")

for i in range(20):
    model_path = MODEL_PATH / f"model{i}.pkl"
    if not model_path.is_file():
        joblib.dump(model,          MODEL_PATH / f"model{i}.pkl")
        joblib.dump(vectorizer,     MODEL_PATH / f"vectorizer{i}.pkl")
        joblib.dump(scaler,         MODEL_PATH / f"scaler{i}.pkl")       
        joblib.dump(method_encoder, MODEL_PATH / f"method_encoder{i}.pkl")
        print(f"Artefatos salvos como versão {i}.")
        break


# -----------------------------------------------------
# Análise de Features
# -----------------------------------------------------


print("\n-- Importância geral (top 20) -------------------------------------------")

text_feature_names = list(vectorizer.get_feature_names_out())
all_features = text_feature_names + numeric_features + method_feature_names

importance = pd.Series(model.feature_importances_, index=all_features)
print(importance.sort_values(ascending=False).head(20).to_string())

print("\n-- Features numéricas ---------------------------------------------------")
print(importance[numeric_features].sort_values(ascending=False).to_string())

print("\n-- Features de método (one-hot) -----------------------------------------")
print(importance[method_feature_names].sort_values(ascending=False).to_string())

print("\n-- Top 15 n-grams textuais ----------------------------------------------")
print(importance[text_feature_names].sort_values(ascending=False).head(15).to_string())

import re, numpy as np, pandas as pd
from scipy.sparse import csr_matrix, hstack
from urllib.parse import unquote
from attack_keywords import SQL_KEYWORDS, XSS_KEYWORDS, RCE_SHELL_OPS, RCE_FUNCTIONS, RCE_SHELL_COMMANDS

# Resumo: Extração de features do modelo de requisição (de acordo com FEATURE)

def extract_features(method: str, request: str, vectorizer, scaler, method_encoder, feature: str):

    req_lower = request.lower()
    request_decoded = unquote(unquote(req_lower))

    req_length       = len(request)

    num_encoded      = len(re.findall(r"%[0-9a-fA-F]{2}", request))

    num_params       = request_decoded.count("=")

    num_plus         = len(re.findall(r"\+", request_decoded))

    num_quotes       = request_decoded.count("'")

    num_special_chars= len(re.findall(r'[<>;"\\]', request_decoded))

    num_traversal = (
        len(re.findall(r"\.\./", request_decoded))             
        + len(re.findall(r"\.\.\\", request_decoded))          
    )

    # SQL Injection
    num_sqlwords = sum(request_decoded.count(w) for w in SQL_KEYWORDS)
    num_sql_comments = len(re.findall(r"--", request_decoded)) + len(re.findall(r"/\*.*?\*/", request))

    # XSS
    num_xsswords = sum(request_decoded.count(w) for w in XSS_KEYWORDS)

    # RCE
    num_shell_ops = sum(request_decoded.count(op) for op in RCE_SHELL_OPS)
    num_rcefuncs  = sum(request_decoded.count(fn) for fn in RCE_FUNCTIONS)
    num_shell_cmds  = sum(request_decoded.count(w)  for w in RCE_SHELL_COMMANDS)


    # ── Vetor numérico — mesma ordem do ML_Treino.py ─────────────────────────
    numeric_values = np.array([[
        req_length,
        num_params,
        num_plus,
        num_quotes,
        num_special_chars,
        num_encoded,
        num_traversal,
        num_sqlwords,
        num_sql_comments,
        num_xsswords,
        num_shell_ops,
        num_rcefuncs,
        num_shell_cmds,
    ]], dtype=float)


    numeric_scaled = scaler.transform(numeric_values)
    X_numeric      = csr_matrix(numeric_scaled)

    X_tfidf = vectorizer.transform([request])

    X_method = method_encoder.transform(pd.DataFrame({"Method":[method.upper()]}))

    if   (feature == "NUM"): X = hstack([X_numeric, X_method])
    elif (feature == "TFI"): X = hstack([X_tfidf, X_method])
    else:                    X = hstack([X_tfidf, X_numeric, X_method])
    
    return X

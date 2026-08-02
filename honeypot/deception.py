from datetime import datetime
import random

# ----------------------------------------------------------------------------------------
# SQL INJECTION 
# ----------------------------------------------------------------------------------------

# Database falso para enganar atacantes
_FAKE_DB = {
    "name": "portal_db",
    "tables": ["usuarios", "processos", "documentos", "sessions", "audit_log"],
    "users": [
        (1, "admin",    "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LkIwhover8a", "superuser"),
        (2, "operator", "$2y$10$KSSNkHMB9ySfPMThNKxnEOFxNDYfhENnm5HJNXPRdPtYQIRTbp4fO", "viewer"),
        (3, "auditor",  "$2y$10$YCrHoE9JiTdT0P7MCBQ63OzFBNt4CRlQEy3ZUijvN45pKjGqOpP7O", "auditor"),
        (4, "jsilva",   "$2y$10$3CiEEFwcGbvBHj0VLqTfNOrXx7MJ5e6IHfhFjGpkNRpqJFRnLcMoa", "viewer"),
    ],
}

def deception_sqli(level: str, page: str = "search") -> tuple:

    line = random.randint(18, 65)

    if level == "low":

        variants = [
            (
                f"Warning: mysqli_fetch_assoc() expects parameter 1 to be mysqli_result, "
                f"boolean given in /var/www/html/{page}.php on line {line}\n"
                f"Error in query: SELECT * FROM {_FAKE_DB['tables'][0]} WHERE id = ..."
            , 500),
            (
                f"SQLSTATE[42000]: Syntax error or access violation: 1064 "
                f"You have an error in your SQL syntax near '\"' at line 1\n"
                f"Failed query on table: {_FAKE_DB['tables'][0]}"
            , 500),
            (
                f"Fatal error: Uncaught mysqli_sql_exception: "
                f"Table '{_FAKE_DB['name']}.{_FAKE_DB['tables'][0]}' doesn't exist "
                f"in /var/www/html/{page}.php:{line}\n"
                f"Stack trace: #0 {page}.php({line}): mysqli_query()"
            , 500),
        ]

        return random.choice(variants)

    if level == "medium":

        tables_str = ", ".join(_FAKE_DB["tables"])

        variants = [
            (
                f"SQLSTATE[42000]: Syntax error near '' at line 1\n"
                f"Database: {_FAKE_DB['name']}\n"
                f"Tables found: {tables_str}\n"
                f"Query log: SELECT id, username, password FROM usuarios LIMIT 10\n"
                f"Hint: Try UNION SELECT on column count 4"
            , 500),
            (
                f"[DB ERROR] Column count mismatch in UNION\n"
                f"Database: {_FAKE_DB['name']}\n"
                f"Table 'usuarios' columns: id (int), username (varchar), "
                f"password_hash (varchar), role (varchar), email (varchar), created_at (datetime)\n"
                f"Adjust UNION SELECT to 6 columns"
            , 500),
            (
                f"[DB ERROR] Partial result before crash:\n"
                f"  id=1, username='admin'\n"
                f"Error: server closed connection after returning 1 row\n"
                f"Remaining rows in '{_FAKE_DB['name']}.usuarios': ~{len(_FAKE_DB['users'])-1}"
            , 500),
        ]
        
        return random.choice(variants)


    # Vazamento de dados falso em três formatos
    rows_table = "\n".join(
        f"  {uid} | {user:<10} | {phash} | {role}"
        for uid, user, phash, role in _FAKE_DB["users"]
    )

    rows_json = ",\n  ".join(
        f'{{"id":{uid},"username":"{user}","password_hash":"{phash}","role":"{role}"}}'
        for uid, user, phash, role in _FAKE_DB["users"]
    )

    rows_extended = "\n".join(
        f"  {uid} | {user:<10} | {phash} | {role:<10} | {user}@portal.gov.br | 2023-0{uid}-15"
        for uid, user, phash, role in _FAKE_DB["users"]
    )

    variants = [
        (
            f"id  | username   | password_hash                                               | role\n"
            f"----+------------+-------------------------------------------------------------+-----------\n"
            f"{rows_table}\n\n"
            f"[{len(_FAKE_DB['users'])} rows returned from {_FAKE_DB['name']}.usuarios]"
        , 200),
        (
            f"[\n  {rows_json}\n]\n\n"
            f"/* {len(_FAKE_DB['users'])} records from {_FAKE_DB['name']}.usuarios */"
        , 200),
        (
            f"id  | username   | password_hash                                               | role       | email                    | created_at\n"
            f"----+------------+-------------------------------------------------------------+------------+--------------------------+-----------\n"
            f"{rows_extended}\n\n"
            f"[{len(_FAKE_DB['users'])} rows — tables also available: {', '.join(_FAKE_DB['tables'][1:])}]"
        , 200),
    ]

    return random.choice(variants)


# ----------------------------------------------------------------------------------------
# CROSS SITE SCRIPTING (XSS)
# ----------------------------------------------------------------------------------------

def deception_xss(payload: str, level: str) -> tuple:

    now = str(datetime.now())[:16]

    if level == "low":

        variants = [
            (
                "<html><head><title>Resultado</title></head><body>"
                f"<p>Busca realizada:</p><div>{payload}</div>"
                "</body></html>"
            , 200),
            (
                "<html><head><title>Portal — Resultados</title></head><body>"
                "<h3>Resultados encontrados:</h3><ul>"
                f"<li>{payload}</li>"
                "</ul><p>1 resultado(s).</p></body></html>"
            , 200),
            (
                "<html><head><title>Erro de validação</title></head><body>"
                f"<p>Entrada inválida detectada: <span style='color:red'>{payload}</span></p>"
                "<p>Por favor revise os dados e tente novamente.</p>"
                "</body></html>"
            , 200),
        ]

        return random.choice(variants)

    if level == "medium":

        variants = [
            (
                "<html><head><title>Painel — Notificações</title></head><body>"
                "<h2>Painel Administrativo — Notificações do Sistema</h2>"
                "<p>Usuário: <strong>admin</strong> | Nível: superuser</p><hr>"
                f"<div class='notification'>{payload}</div>"
                f"<p><small>Notificação registrada em: {now}</small></p>"
                "</body></html>"
            , 200),
            (
                "<html><head><title>Audit Log — SGI</title></head><body>"
                "<h2>Log de Auditoria do Sistema</h2>"
                "<table border='1'><tr><th>Timestamp</th><th>Usuário</th><th>Ação</th></tr>"
                f"<tr><td>{now}</td><td>admin</td><td>{payload}</td></tr>"
                "<tr><td>2024-03-07 14:22</td><td>operator</td><td>Login bem-sucedido</td></tr>"
                "</table></body></html>"
            , 200),
            (
                "<html><head><title>Suporte — Ticket #4821</title></head><body>"
                "<h2>Ticket de Suporte #4821</h2>"
                "<p><b>Status:</b> Aberto | <b>Prioridade:</b> Alta</p>"
                f"<p><b>Descrição:</b> {payload}</p>"
                f"<p><small>Aberto em: {now} por: visitante</small></p>"
                "</body></html>"
            , 200),
        ]

        return random.choice(variants)


    variants = [
        (
            "<html><head><title>Painel — Mural de Mensagens</title></head><body>"
            "<h2>Mural de Mensagens — Acesso Restrito</h2>"
            "<div style='border:1px solid #ccc;margin:8px;padding:8px'>"
            "  <b>admin</b> (2024-03-01): Reunião de equipe amanhã às 10h.</div>"
            "<div style='border:1px solid #ccc;margin:8px;padding:8px'>"
            "  <b>operator</b> (2024-03-05): Relatório mensal enviado.</div>"
            "<div style='border:1px solid #ccc;margin:8px;padding:8px'>"
            f"  <b>visitante</b> ({now}): {payload}</div>"
            "<p><small>3 mensagens — armazenadas no banco</small></p>"
            "</body></html>"
        , 200),
        (
            "<html><head><title>Perfil — jsilva</title></head><body>"
            "<h2>Perfil do Usuário</h2>"
            "<p><b>Nome:</b> João Silva | <b>Role:</b> viewer</p>"
            f"<p><b>Bio:</b> {payload}</p>"
            "<p><b>Último acesso:</b> 2024-03-08 09:41</p>"
            "<p><small>Dados do perfil armazenados em portal_db.usuarios</small></p>"
            "</body></html>"
        , 200),
        (
            "<html><head><title>Comunicados — Admin</title></head><body>"
            "<h2>Comunicados Internos</h2>"
            "<div style='background:#f5f5f5;padding:10px;margin:8px'>"
            "  <b>[admin]</b> Manutenção programada para domingo 02:00h.</div>"
            "<div style='background:#f5f5f5;padding:10px;margin:8px'>"
            f"  <b>[visitante — {now}]</b> {payload}</div>"
            "<p><small>2 comunicados ativos — visíveis para todos os usuários</small></p>"
            "</body></html>"
        , 200),
    ]

    return random.choice(variants)


# ----------------------------------------------------------------------------------------
# REMOTE CODE EXECUTION (RCE)
# ----------------------------------------------------------------------------------------

def deception_rce(level: str) -> tuple:

    if level == "low":

        variants = [
            ("www-data\n", 200),
            ("portal-srv-prod-01\n", 200),
            ("/var/www/html\nuid=33(www-data) gid=33(www-data)\n", 200),
        ]

        return random.choice(variants)

    if level == "medium":

        variants = [
            (
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n"
                "total 64\n"
                "drwxr-xr-x 4 www-data www-data 4096 Mar  8 10:42 .\n"
                "drwxr-xr-x 5 root     root     4096 Jan 12 08:00 ..\n"
                "-rw-r--r-- 1 www-data www-data 3201 Mar  8 10:42 index.php\n"
                "-rw-r--r-- 1 www-data www-data 5471 Mar  5 14:33 login.php\n"
                "-rw-r--r-- 1 www-data www-data 2018 Feb 20 09:11 config.php\n"
                "-rw-r--r-- 1 www-data www-data  891 Jan 30 16:55 .htaccess\n"
                "drwxr-xr-x 2 www-data www-data 4096 Mar  1 11:20 uploads\n"
                "drwxr-xr-x 2 root     root     4096 Jan 12 08:00 backup\n"
            , 200),
            (
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n"
                "/var/www/html/config.php\n"
                "/var/www/html/login.php\n"
                "/var/www/html/search.php\n"
                "/var/www/html/cron/backup.php\n"
                "/var/www/html/cron/sync.php\n"
                "/var/www/html/includes/db.php\n"
                "/var/www/html/includes/auth.php\n"
                "/var/www/html/admin/users.php\n"
            , 200),
            (
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n"
                "<?php\n"
                "// /var/www/html/includes/db.php\n"
                "define('DB_HOST', 'localhost');\n"
                "define('DB_USER', 'portal_user');\n"
                "define('DB_PASS', 's3cr3t_p4ss');\n"
                "define('DB_NAME', 'portal_db');\n"
                "$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);\n"
                "if (!$conn) die('Connection failed: ' . mysqli_connect_error());\n"
                "?>\n"
            , 200),
        ]

        return random.choice(variants)


    variants = [
        (
            "# uname -a\n"
            "Linux portal-srv-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n\n"
            "# ps aux | grep -E 'apache|mysql|php'\n"
            "root       812  0.0  0.1  18936  3012 ?  Ss   Mar08   0:00 /usr/sbin/apache2 -k start\n"
            "www-data  1047  0.0  0.5 353812 11204 ?  S    Mar08   0:12 /usr/sbin/apache2 -k start\n"
            "mysql      923  0.2  3.1 1823440 63840 ?  Ssl  Mar08   8:44 /usr/sbin/mysqld\n\n"
            "# ss -tlnp\n"
            "LISTEN 0  80   127.0.0.1:3306  (mysqld)\n"
            "LISTEN 0  511  0.0.0.0:80      (apache2)\n"
            "LISTEN 0  511  0.0.0.0:443     (apache2)\n"
            "LISTEN 0  128  0.0.0.0:22      (sshd)\n"
        , 200),
        (
            "# uname -a\n"
            "Linux portal-srv-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n\n"
            "# ip addr show eth0\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n"
            "    inet6 fe80::1/64 scope link\n\n"
            "# env | grep -E 'PATH|HOME|USER|APACHE|PHP'\n"
            "USER=www-data\n"
            "HOME=/var/www\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "APACHE_RUN_USER=www-data\n"
            "APACHE_RUN_GROUP=www-data\n"
            "APACHE_LOG_DIR=/var/log/apache2\n"
            "PHP_INI_SCAN_DIR=/etc/php/7.4/apache2/conf.d\n"
        , 200),
        (
            "# uname -a\n"
            "Linux portal-srv-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n\n"
            "# crontab -l\n"
            "*/5 * * * * /usr/bin/php /var/www/html/cron/sync.php\n"
            "0 2 * * * /usr/bin/php /var/www/html/cron/backup.php\n\n"
            "# tail -5 /var/log/apache2/portal_access.log\n"
            "10.0.0.1 - - [09/Mar/2024:03:10:01] \"GET /search?q=relatorio HTTP/1.1\" 200 4821\n"
            "10.0.0.1 - - [09/Mar/2024:03:10:44] \"POST /login HTTP/1.1\" 302 -\n"
            "10.0.0.1 - - [09/Mar/2024:03:11:02] \"GET /login/admin HTTP/1.1\" 200 8934\n"
            "10.0.0.1 - - [09/Mar/2024:03:12:18] \"GET /.env HTTP/1.1\" 200 312\n"
            "10.0.0.1 - - [09/Mar/2024:03:14:55] \"GET /.git/config HTTP/1.1\" 200 187\n"
        , 200),
    ]
    
    return random.choice(variants)


# ----------------------------------------------------------------------------------------
# LOCAL FILE INJECTION (LFI)
# ----------------------------------------------------------------------------------------

_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n"
    "portal:x:1001:1001:Portal App,,,:/home/portal:/bin/bash\n"
    "jsilva:x:1002:1002:João Silva,,,:/home/jsilva:/bin/bash\n"
)

_FAKE_APACHE_CONF = (
    "ServerName portal.gov.br\n"
    "DocumentRoot /var/www/html\n"
    "DirectoryIndex index.php index.html\n"
    "<Directory /var/www/html>\n"
    "    AllowOverride All\n"
    "    Require all granted\n"
    "</Directory>\n"
    "ErrorLog /var/log/apache2/portal_error.log\n"
    "CustomLog /var/log/apache2/portal_access.log combined\n"
)

_FAKE_SHADOW = (
    "root:$6$rounds=5000$nacl1234567890ab$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:19800:0:99999:7:::\n"
    "portal:$6$rounds=5000$slt9876543210xy$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:19800:0:99999:7:::\n"
    "jsilva:$6$rounds=5000$rnd5432198760zw$CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:19745:0:99999:7:::\n"
)

def deception_lfi(level: str) -> tuple:

    if level == "low":

        variants = [
            (_FAKE_PASSWD, 200),
            (
                "# /etc/hostname\nportal-srv-prod-01\n\n"
                "# /etc/issue\nUbuntu 20.04.6 LTS \\n \\l\n\n"
                "# /etc/os-release\n"
                "NAME=\"Ubuntu\"\nVERSION=\"20.04.6 LTS (Focal Fossa)\"\n"
                "ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\n"
                "VERSION_ID=\"20.04\"\nHOME_URL=\"https://www.ubuntu.com/\"\n"
            , 200),
            (
                "<?php\n"
                "// /var/www/html/config.php\n"
                "define('DB_HOST', 'localhost');\n"
                "define('DB_USER', 'portal_user');\n"
                "define('DB_PASS', 's3cr3t_p4ss');\n"
                "define('DB_NAME', 'portal_db');\n"
                "define('APP_KEY', '3f8a2b1c9d4e5f6071828394a5b6c7d8');\n"
                "define('UPLOAD_DIR', '/var/www/html/uploads/');\n"
                "$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);\n"
                "?>\n"
            , 200),
        ]

        return random.choice(variants)

    if level == "medium":

        variants = [
            (
                "# /etc/passwd\n" + _FAKE_PASSWD +
                "\n# /etc/apache2/sites-enabled/portal.conf\n" + _FAKE_APACHE_CONF +
                "\n# /var/www/html/.htaccess\n"
                "RewriteEngine On\n"
                "RewriteRule ^config\\.php$ - [F,L]\n"
                "php_value session.save_path /var/lib/php/sessions\n"
            , 200),
            (
                "# /etc/passwd\n" + _FAKE_PASSWD +
                "\n# /etc/php/7.4/apache2/php.ini (relevant sections)\n"
                "allow_url_fopen = On\n"
                "allow_url_include = On\n"
                "disable_functions =\n"
                "file_uploads = On\n"
                "upload_max_filesize = 20M\n"
                "session.save_path = /var/lib/php/sessions\n"
                "session.name = PHPSESSID\n"
                "\n# /var/lib/php/sessions/ — session files readable by www-data\n"
            , 200),
            (
                "# /etc/passwd\n" + _FAKE_PASSWD +
                "\n# /var/spool/cron/crontabs/www-data\n"
                "*/5 * * * * /usr/bin/php /var/www/html/cron/sync.php >> /var/log/sync.log 2>&1\n"
                "0 2 * * * /usr/bin/php /var/www/html/cron/backup.php\n"
                "0 4 * * 0 /bin/bash /var/www/html/cron/cleanup.sh\n"
                "\n# /var/log/apache2/portal_error.log (last 3 lines)\n"
                "[Sat Mar 09 03:12:41 2024] [error] PHP Warning: mysqli_connect() "
                "[function.mysqli-connect]: Access denied for user 'backup'@'localhost'\n"
            , 200),
        ]
        return random.choice(variants)


    variants = [
        (
            "# /etc/shadow\n" + _FAKE_SHADOW +
            "\n# Tip: hashes are SHA-512 ($6$), 5000 rounds"
        , 200),
        (
            "# /etc/shadow\n" + _FAKE_SHADOW +
            "\n# /home/portal/.bash_history\n"
            "mysql -u portal_user -ps3cr3t_p4ss portal_db\n"
            "cd /var/www/html && git pull\n"
            "sudo systemctl restart apache2\n"
            "cat /var/log/apache2/portal_access.log | grep 'POST /login'\n"
            "mysqldump -u portal_user -ps3cr3t_p4ss portal_db > /tmp/backup.sql\n"
        , 200),
        (
            "# /etc/shadow\n" + _FAKE_SHADOW +
            "\n# /home/portal/.ssh/authorized_keys\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2fake+key+content"
            "ZmFrZWtleWNvbnRlbnQ= deploy@portal-srv-prod-01\n"
            "\n# /home/jsilva/.ssh/authorized_keys\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDanother+fake+key"
            "ZmFrZWtleWNvbnRlbnQ= jsilva@workstation\n"
        , 200),
    ]
    return random.choice(variants)

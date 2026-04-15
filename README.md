# 🔑 Mordomo Vault

## 🔗 Navegação

**[🏠 AslamSys](https://github.com/AslamSys)** → **[📚 _system](https://github.com/AslamSys/_system)** → **[📂 Aslam (Orange Pi 5 16GB)](https://github.com/AslamSys/_system/blob/main/hardware/mordomo%20-%20(orange-pi-5-16gb)/README.md)** → **mordomo-vault**

### Containers Relacionados (mordomo)
- [mordomo-speaker-verification](https://github.com/AslamSys/mordomo-speaker-verification)
- [mordomo-orchestrator](https://github.com/AslamSys/mordomo-orchestrator)
- [mordomo-brain](https://github.com/AslamSys/mordomo-brain)
- [mordomo-openclaw-agent](https://github.com/AslamSys/mordomo-openclaw-agent)
- [mordomo-financas-pix](https://github.com/AslamSys/mordomo-financas-pix)
- [mordomo-people](https://github.com/AslamSys/mordomo-people)

### Consumers externos (cross-ecossistema)
- [investimentos-trading-bot](https://github.com/AslamSys/investimentos-trading-bot)
- [investimentos-betting-bot](https://github.com/AslamSys/investimentos-betting-bot)

---

**Container:** `mordomo-vault`
**Ecossistema:** Mordomo Central
**Hardware:** Orange Pi 5 16GB
**Stack:** Python + SQLite (SQLCipher) + AES-256-GCM

---

## 📋 Propósito

Cofre central de credenciais do sistema. Armazena API keys, tokens e senhas criptografados com AES-256-GCM, e os libera apenas mediante política de autorização — que pode exigir confirmação biométrica de voz (`voice`) ou autenticação de módulo autônomo (`service`).

**Integração central com `mordomo-speaker-verification`:** quando uma ação é iniciada por voz, o `person_id` + `confidence` da sessão ativa são usados como fator de autorização para liberar o segredo correspondente.

---

## 🎯 Responsabilidades

- ✅ Armazenar credenciais criptografadas (AES-256-GCM, key derivada do `VAULT_MASTER_KEY`)
- ✅ Autorizar acesso via **voz** (`person_id` + `confidence` do speaker-verification)
- ✅ Autorizar acesso via **token de módulo** para processos autônomos (sem voz)
- ✅ Aplicar política por segredo: quem pode pedir, de qual módulo, com qual confiança mínima
- ✅ Registrar auditoria completa de cada acesso (concedido ou negado)
- ✅ **Nunca expor o valor em logs** — apenas audit metadata

---

## 🔐 Dois Modos de Autenticação

### 1. `voice` — Iniciado por voz
Usado quando o usuário verbalizou a ação. O `mordomo-orchestrator` inclui o contexto da sessão.

```
Usuário fala: "Faz um PIX de R$500 pro João"
       ↓
mordomo-speaker-verification → { person_id: "renan", confidence: 0.97 }
       ↓
mordomo-orchestrator → passa { person_id, confidence } na requisição ao vault
       ↓
mordomo-vault → verifica política: confidence >= 0.95? person_id autorizado? módulo permitido?
       ↓ (sim)
mordomo-financas-pix ← recebe ASAAS_API_KEY → executa
```

### 2. `service` — Módulo autônomo
Usado por processos que rodam sem interação de voz (investimentos, agendamento, etc.). O módulo autentica com seu `MODULE_TOKEN` pré-emitido.

```
investimentos-trading-bot (cron scan)
       ↓
mordomo-vault.secret.get → { secret_key: "binance_api_key", module_token: "***" }
       ↓
vault verifica: token válido? módulo autorizado para essa key?
       ↓ (sim)
investimentos-trading-bot ← recebe BINANCE_API_KEY → executa trade
```

---

## 📦 Segredos Gerenciados

| secret_key | Módulo consumidor | Auth mode | Pessoa autorizada | Confiança mínima |
|---|---|---|---|---|
| `asaas_api_key` | mordomo-financas-pix | `voice` | `owner` | 0.95 |
| `bb_cert` | mordomo-financas-pix | `voice` | `owner` | 0.95 |
| `inter_api_key` | mordomo-financas-pix | `voice` | `owner` | 0.95 |
| `openai_api_key` | mordomo-brain | `service` | — | — |
| `anthropic_api_key` | mordomo-brain | `service` | — | — |
| `groq_api_key` | mordomo-brain | `service` | — | — |
| `google_ai_api_key` | mordomo-brain | `service` | — | — |
| `telegram_bot_token` | mordomo-openclaw-agent | `service` | — | — |
| `discord_bot_token` | mordomo-openclaw-agent | `service` | — | — |
| `twilio_sid` | mordomo-openclaw-agent | `service` | — | — |
| `twilio_token` | mordomo-openclaw-agent | `service` | — | — |
| `smtp_password` | mordomo-openclaw-agent | `service` | — | — |
| `binance_api_key` | investimentos-trading-bot | `service` | — | — |
| `binance_secret` | investimentos-trading-bot | `service` | — | — |
| `bybit_api_key` | investimentos-trading-bot | `service` | — | — |
| `bybit_secret` | investimentos-trading-bot | `service` | — | — |
| `bet365_username` | investimentos-betting-bot | `service` | — | — |
| `bet365_password` | investimentos-betting-bot | `service` | — | — |

> **Nota:** Segredos `service` não exigem voz pois os módulos operam de forma autônoma (investimentos, bots). O acesso é restrito ao módulo específico via `MODULE_TOKEN`. Segredos `voice` (financas) exigem confirmação biométrica porque envolvem movimentação financeira iniciada pelo usuário.

---

## 🗄️ Schema (SQLite + SQLCipher)

```sql
-- Segredos criptografados
CREATE TABLE secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_key      TEXT UNIQUE NOT NULL,
    encrypted_value BLOB NOT NULL,  -- AES-256-GCM
    nonce           BLOB NOT NULL,  -- 12 bytes
    description     TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Políticas de acesso por segredo
CREATE TABLE policies (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_key          TEXT NOT NULL REFERENCES secrets(secret_key),
    auth_mode           TEXT NOT NULL CHECK (auth_mode IN ('voice', 'service')),
    allowed_person_ids  TEXT,        -- JSON array, null = qualquer pessoa autenticada
    min_confidence      REAL,        -- válido apenas para auth_mode='voice'
    allowed_modules     TEXT NOT NULL,  -- JSON array de módulos autorizados
    module_token_hash   TEXT,           -- SHA-256 do MODULE_TOKEN, para auth_mode='service'
    enabled             BOOLEAN DEFAULT 1
);

-- Auditoria completa (nunca contém o valor do segredo)
CREATE TABLE audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_key       TEXT NOT NULL,
    requester_module TEXT NOT NULL,
    auth_mode        TEXT NOT NULL,
    person_id        TEXT,            -- preenchido em mode='voice'
    confidence       REAL,            -- preenchido em mode='voice'
    granted          BOOLEAN NOT NULL,
    denial_reason    TEXT,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🔌 NATS Interface

### Subscribe (recebe requisições)

```yaml
mordomo.vault.secret.get:
  Descrição: Requisição de segredo (request/reply)
  Payload (voice):
    secret_key: "asaas_api_key"
    requester_module: "mordomo-financas-pix"
    auth_mode: "voice"
    person_id: "renan"
    confidence: 0.97
  Payload (service):
    secret_key: "binance_api_key"
    requester_module: "investimentos-trading-bot"
    auth_mode: "service"
    module_token: "***"

mordomo.vault.policy.reload:
  Descrição: Recarrega políticas do banco (admin only)
  Payload: {}
```

### Publish (respostas e auditoria)

```yaml
Reply (NATS request/reply — success):
  value: "<secret decryptado>"

Reply (NATS request/reply — denied):
  error: "unauthorized"
  reason: "confidence_too_low | person_not_allowed | module_not_allowed | token_invalid"

mordomo.vault.audit:
  Descrição: Publicado após cada tentativa de acesso
  Payload:
    secret_key: "asaas_api_key"
    requester_module: "mordomo-financas-pix"
    granted: true
    person_id: "renan"
    confidence: 0.97
    timestamp: "2026-04-13T12:00:00Z"
```

---

## 🔄 Fluxo Completo (voice)

```
wake_word.detected
       ↓
mordomo-speaker-verification
   → publica: speaker.verified { person_id: "renan", confidence: 0.97 }
       ↓
mordomo-orchestrator (Session Controller)
   → mantém sessão: { active_person_id: "renan", confidence: 0.97 }
       ↓
mordomo-brain → interpreta intenção → { action: "pix", amount: 500, to: "João" }
       ↓
mordomo-orchestrator (Action Dispatcher)
   → antes de despachar para mordomo-financas-pix:
   → mordomo.vault.secret.get { secret_key: "asaas_api_key", auth_mode: "voice",
                                  person_id: "renan", confidence: 0.97,
                                  requester_module: "mordomo-financas-pix" }
       ↓
mordomo-vault
   → verifica política: confidence(0.97) >= 0.95 ✅ | person_id "renan" = owner ✅
   → decripta ASAAS_API_KEY → responde no reply
   → publica audit log
       ↓
mordomo-orchestrator
   → despacha para mordomo-financas-pix com a API key na mensagem (efêmera, não persiste)
       ↓
mordomo-financas-pix → executa PIX
```

---

## 🔄 Fluxo Completo (service)

```
investimentos-trading-bot (cron a cada 5min)
   → mordomo.vault.secret.get { secret_key: "binance_api_key",
                                  auth_mode: "service",
                                  requester_module: "investimentos-trading-bot",
                                  module_token: "${VAULT_MODULE_TOKEN}" }
       ↓
mordomo-vault
   → verifica: SHA256(module_token) == hash da tabela policies ✅
   → módulo "investimentos-trading-bot" está na allowed_modules ✅
   → decripta → responde
       ↓
investimentos-trading-bot ← BINANCE_API_KEY (usado em memória, não em disco)
```

---

## 🚀 Docker Compose

```yaml
services:
  mordomo-vault:
    build: .
    container_name: mordomo-vault
    environment:
      - NATS_URL=nats://mordomo-nats:4222
      - VAULT_MASTER_KEY=${VAULT_MASTER_KEY}   # AES-256 master key — nunca vai para o repo
      - VAULT_DB_PATH=/data/vault.db            # SQLite + SQLCipher
    volumes:
      - vault-data:/data                        # DB criptografado
    networks:
      - mordomo-net
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.2'
          memory: 128M

volumes:
  vault-data:
```

> **Segurança:** `VAULT_MASTER_KEY` nunca entra no repositório. É configurado manualmente no `.env` de produção de cada máquina. A perda desta chave é irreversível — fazer backup em local separado e seguro.

---

## 🔑 Bootstrap de Módulos

Ao inicializar o sistema, cada módulo com `auth_mode: service` recebe um `MODULE_TOKEN` único:

```bash
# Gerar token para um módulo (executar no vault)
python vault_cli.py issue-token --module investimentos-trading-bot
# → VAULT_MODULE_TOKEN=vtk_abc123... (adicionar no .env do módulo)

# Revogar token
python vault_cli.py revoke-token --module investimentos-trading-bot
```

---

## 📊 Integração com mordomo-people

O vault usa `person_id` da sessão (vindo do `mordomo-speaker-verification`) para checar permissão, mas **não armazena perfis de pessoa** — isso é responsabilidade do `mordomo-people`. O vault apenas compara o `person_id` recebido com a lista `allowed_person_ids` da política.

```
mordomo-people → "renan" tem is_owner=true → flag usada para definir a política no vault
mordomo-speaker-verification → identifica "renan" em tempo real → passa person_id ao vault
mordomo-vault → checa: "renan" está em allowed_person_ids? → concede ou nega
```

---

## 📊 Estimativa de Recursos

| Componente | RAM | CPU |
|---|---|---|
| Python runtime + NATS client | 40 MB | < 1% |
| SQLCipher + cache de políticas | 20 MB | < 1% |
| Criptografia AES-256-GCM | negligível | pico no decrypt |
| **TOTAL** | **~60 MB** | **< 1%** |

---

## 🗂️ Estrutura do Repositório

```
mordomo-vault/
├── src/
│   ├── config.py      # Env vars, NATS subjects, VAULT_MASTER_KEY loading
│   ├── crypto.py      # AES-256-GCM encrypt/decrypt (nonce gerado por request)
│   ├── db.py          # SQLite: secrets, policies, audit_log
│   ├── policies.py    # Engine de autorização (voice + service)
│   ├── handlers.py    # NATS handlers: secret.get, policy.reload
│   └── main.py        # Entrypoint asyncio + reconnect loop
├── vault_cli.py        # CLI de bootstrap: set-secret, add-policy, issue-token, revoke-token
├── requirements.txt    # nats-py==2.6.0, cryptography==42.0.8
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## 🚀 Bootstrap (primeira vez)

```bash
# 1. Gerar VAULT_MASTER_KEY
python -c "import os,binascii; print(binascii.hexlify(os.urandom(32)).decode())"
# → copiar para .env como VAULT_MASTER_KEY=<hex>

# 2. Subir container
docker compose up -d

# 3. Dentro do container: cadastrar segredos
docker exec -it mordomo-vault python vault_cli.py set-secret \
  --key asaas_api_key --value "sk_live_..." --desc "ASAAS payment key"

# 4. Adicionar política de voz (financeiro)
docker exec -it mordomo-vault python vault_cli.py add-policy \
  --key asaas_api_key --mode voice \
  --modules mordomo-financas-pix --persons owner --min-confidence 0.95

# 5. Adicionar política de serviço (autônomo) + emitir token
docker exec -it mordomo-vault python vault_cli.py add-policy \
  --key binance_api_key --mode service --modules investimentos-trading-bot

docker exec -it mordomo-vault python vault_cli.py issue-token \
  --module investimentos-trading-bot
# → VAULT_MODULE_TOKEN=vtk_... (adicionar no .env do módulo)
```

## 🔑 Variáveis de Ambiente

| Variável | Obrigatório | Descrição |
|---|---|---|
| `VAULT_MASTER_KEY` | ✅ | 64 hex chars (32 bytes). Nunca ao repo. Backup obrigatório. |
| `NATS_URL` | ✅ | Ex: `nats://mordomo-nats:4222` |
| `VAULT_DB_PATH` | — | Default: `/data/vault.db` (volume persistente) |

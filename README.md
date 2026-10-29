# Jundiaí Participativa

Node.js + Express + PostgreSQL. As tabelas são criadas sozinhas na primeira execução.

## Rodar local
    npm install
    cp .env.example .env   # preencha e exporte as variáveis
    DATABASE_SSL=false NODE_ENV=development npm start

## Deploy no Render
1. Suba esta pasta para um repositório no GitHub.
2. Banco: crie um PostgreSQL (Render, Neon ou Supabase) e copie a connection string (Internal URL se for no Render).
3. Render > New > Web Service > conecte o repositório.
   - Build Command: `npm install`
   - Start Command: `npm start`
4. Em Environment, adicione as variáveis de `.env.example`.
5. Deploy. Entre com ADMIN_EMAIL/ADMIN_PASSWORD em /entrar para abrir o painel (/admin).

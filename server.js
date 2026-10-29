const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const prod = process.env.NODE_ENV === 'production';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
});
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.static('public'));
app.use(session({
  store: new PgStore({ pool, createTableIfMissing: true }),
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'troque-isto',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 7 * 864e5 },
}));
app.use((req, res, next) => { res.locals.user = req.session.user || null; next(); });

const CATEGORIAS = ['Poda de árvore', 'Bueiro / boca de lobo', 'Buraco na rua', 'Iluminação pública', 'Limpeza / entulho', 'Outro'];
const STATUS = ['Recebida', 'Em análise', 'Encaminhada', 'Concluída', 'Não procede'];

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = d => new Date(d).toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
const digits = s => String(s || '').replace(/\D/g, '');
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).send(page(res, 'Erro', '<h1>Algo deu errado</h1><p>Tente novamente em instantes.</p>')); });
const needLogin = (req, res, next) => req.session.user ? next() : res.redirect('/entrar');
const needAdmin = (req, res, next) => req.session.user?.papel === 'admin' ? next() : res.status(403).send(page(res, 'Acesso negado', '<h1>Acesso negado</h1>'));

function page(res, title, body) {
  const u = res.locals.user;
  const nav = u
    ? `<a href="/solicitar">Nova solicitação</a><a href="/minhas-solicitacoes">Minhas solicitações</a>${u.papel === 'admin' ? '<a href="/admin">Painel</a>' : ''}<form method="post" action="/sair"><button class="link">Sair</button></form>`
    : '<a href="/solicitar">Nova solicitação</a><a href="/entrar">Entrar</a><a href="/cadastro">Criar conta</a>';
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Jundiaí Participativa</title><link rel="stylesheet" href="/style.css"></head><body>
<header><a class="brand" href="/">Jundiaí Participativa</a><nav>${nav}</nav></header>
<main>${body}</main>
<footer><p>Atendimento exclusivo para moradores de Jundiaí/SP. Este site usa apenas cookies essenciais. <a href="/privacidade">Privacidade e LGPD</a></p></footer>
<div id="cookie" hidden><p>Usamos somente cookies essenciais (sessão de login e segurança). Não usamos cookies de publicidade ou rastreamento. <a href="/privacidade">Saiba mais</a></p><button id="cookie-ok">Entendi</button></div>
<script src="/app.js"></script></body></html>`;
}
const err = e => e ? `<p class="erro" role="alert">${esc(e)}</p>` : '';
const consent = `<label class="check"><input type="checkbox" name="consent" value="1" required> Li a <a href="/privacidade" target="_blank">Política de Privacidade</a> e autorizo o uso dos meus dados para atender esta solicitação.</label>`;

// ---------- páginas públicas ----------
app.get('/', (req, res) => res.send(page(res, 'Início', `
<section class="hero"><h1>Viu um problema no seu bairro? Conte para a gente.</h1>
<p>Registre pedidos como poda de árvore, bueiro entupido ou buraco na rua. Você recebe um protocolo e acompanha o andamento.</p>
<p><a class="btn" href="/solicitar">Registrar solicitação</a></p></section>`)));

app.get('/privacidade', (req, res) => res.send(page(res, 'Privacidade', `
<article class="texto"><h1>Política de Privacidade (LGPD)</h1>
<p><em>Modelo inicial. Revise com um advogado e preencha os dados do controlador antes de publicar.</em></p>
<h2>Quem é o controlador</h2><p>[NOME / RAZÃO SOCIAL], [CNPJ/CPF], [ENDEREÇO]. Contato do encarregado (DPO): [E-MAIL].</p>
<h2>Quais dados coletamos</h2><p>Nome, endereço, bairro, cidade, telefone, e-mail (opcional) e o conteúdo da sua solicitação. Para contas: e-mail e senha (armazenada apenas em formato criptografado/hash).</p>
<h2>Finalidade e base legal</h2><p>Registrar, acompanhar e responder às solicitações de moradores de Jundiaí. Base legal: consentimento (art. 7º, I, LGPD), que você fornece ao marcar a caixa de autorização nos formulários.</p>
<h2>Compartilhamento</h2><p>Seus dados podem ser encaminhados aos órgãos responsáveis pela execução do serviço solicitado e a provedores de infraestrutura (hospedagem e banco de dados). Não vendemos dados.</p>
<h2>Cookies</h2><p>Usamos apenas um cookie essencial de sessão (<code>sid</code>), necessário para login e segurança. Não usamos cookies de análise, publicidade ou rastreamento.</p>
<h2>Retenção</h2><p>Mantemos os dados enquanto forem necessários para a finalidade ou até você pedir a exclusão. [DEFINIR PRAZO].</p>
<h2>Seus direitos (art. 18)</h2><p>Confirmação de tratamento, acesso, correção, anonimização, exclusão, portabilidade, informação sobre compartilhamento e revogação do consentimento. Quem tem conta pode excluí-la em <a href="/minhas-solicitacoes">Minhas solicitações</a>. Para outros pedidos, escreva para [E-MAIL].</p>
</article>`)));

// ---------- conta ----------
app.get('/cadastro', (req, res) => res.send(page(res, 'Criar conta', formCadastro({}))));
function formCadastro(v, e) {
  return `<h1>Criar conta</h1>${err(e)}<form method="post" action="/cadastro" class="form">
<label>Nome completo<input name="nome" required maxlength="120" value="${esc(v.nome)}"></label>
<label>E-mail<input type="email" name="email" required maxlength="160" value="${esc(v.email)}"></label>
<label>Celular com DDD<input name="telefone" inputmode="tel" required maxlength="20" value="${esc(v.telefone)}"></label>
<label>Senha (mínimo 8 caracteres)<input type="password" name="senha" required minlength="8" maxlength="72" autocomplete="new-password"></label>
${consent}<button class="btn">Criar conta</button></form>`;
}
app.post('/cadastro', wrap(async (req, res) => {
  const { nome, email, telefone, senha, consent: c } = req.body;
  const tel = digits(telefone);
  const bad = !nome?.trim() || !/^\S+@\S+\.\S+$/.test(email || '') || tel.length < 10 || tel.length > 11 || (senha || '').length < 8 || !c;
  if (bad) return res.status(400).send(page(res, 'Criar conta', formCadastro(req.body, 'Confira os campos e aceite a política de privacidade.')));
  try {
    const hash = await bcrypt.hash(senha, 12);
    const { rows } = await pool.query('INSERT INTO usuarios(nome,email,telefone,senha_hash) VALUES($1,$2,$3,$4) RETURNING id,nome,papel',
      [nome.trim(), email.trim().toLowerCase(), tel, hash]);
    req.session.regenerate(() => { req.session.user = rows[0]; res.redirect('/solicitar'); });
  } catch (e) {
    if (e.code === '23505') return res.status(400).send(page(res, 'Criar conta', formCadastro(req.body, 'Este e-mail já tem cadastro. Tente entrar.')));
    throw e;
  }
}));

const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const formLogin = e => `<h1>Entrar</h1>${err(e)}<form method="post" action="/entrar" class="form">
<label>E-mail<input type="email" name="email" required autocomplete="username"></label>
<label>Senha<input type="password" name="senha" required autocomplete="current-password"></label>
<button class="btn">Entrar</button></form><p>Ainda não tem conta? <a href="/cadastro">Criar conta</a></p>`;
app.get('/entrar', (req, res) => res.send(page(res, 'Entrar', formLogin())));
app.post('/entrar', loginLimit, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM usuarios WHERE email=$1', [String(req.body.email || '').trim().toLowerCase()]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(req.body.senha || '', u.senha_hash)))
    return res.status(401).send(page(res, 'Entrar', formLogin('E-mail ou senha incorretos.')));
  req.session.regenerate(() => { req.session.user = { id: u.id, nome: u.nome, papel: u.papel }; res.redirect(u.papel === 'admin' ? '/admin' : '/minhas-solicitacoes'); });
}));
app.post('/sair', (req, res) => req.session.destroy(() => res.redirect('/')));

// ---------- solicitações ----------
async function formSolicitar(req, v, e) {
  let d = v;
  if (!Object.keys(v).length && req.session.user) {
    const { rows } = await pool.query('SELECT nome,email,telefone FROM usuarios WHERE id=$1', [req.session.user.id]);
    d = rows[0] || {};
  }
  return `<h1>Nova solicitação</h1><p>Atendemos apenas Jundiaí/SP.</p>${err(e)}<form method="post" action="/solicitar" class="form">
<label>Nome completo<input name="nome" required maxlength="120" value="${esc(d.nome)}"></label>
<label>Celular com DDD<input name="telefone" inputmode="tel" required maxlength="20" value="${esc(d.telefone)}"></label>
<label>E-mail (opcional)<input type="email" name="email" maxlength="160" value="${esc(d.email)}"></label>
<label>Endereço (rua e número)<input name="endereco" required maxlength="200" value="${esc(d.endereco)}"></label>
<label>Bairro<input name="bairro" required maxlength="100" value="${esc(d.bairro)}"></label>
<label>Cidade<input value="Jundiaí" disabled></label>
<label>Tipo de solicitação<select name="categoria" required>${CATEGORIAS.map(c => `<option ${d.categoria === c ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
<label>Descreva o problema<textarea name="descricao" rows="5" required maxlength="2000">${esc(d.descricao)}</textarea></label>
${consent}<button class="btn">Enviar solicitação</button></form>`;
}
app.get('/solicitar', wrap(async (req, res) => res.send(page(res, 'Nova solicitação', await formSolicitar(req, {})))));
app.post('/solicitar', wrap(async (req, res) => {
  const b = req.body, tel = digits(b.telefone);
  const bad = !b.nome?.trim() || !b.endereco?.trim() || !b.bairro?.trim() || !b.descricao?.trim() || tel.length < 10 || tel.length > 11 || !CATEGORIAS.includes(b.categoria) || !b.consent;
  if (bad) return res.status(400).send(page(res, 'Nova solicitação', await formSolicitar(req, b, 'Confira os campos e aceite a política de privacidade.')));
  const protocolo = 'JP-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  await pool.query(`INSERT INTO solicitacoes(protocolo,usuario_id,nome,endereco,bairro,telefone,email,categoria,descricao) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [protocolo, req.session.user?.id || null, b.nome.trim(), b.endereco.trim(), b.bairro.trim(), tel, b.email?.trim() || null, b.categoria, b.descricao.trim()]);
  res.send(page(res, 'Recebido', `<h1>Solicitação recebida</h1><p>Seu protocolo é <strong class="protocolo">${protocolo}</strong>. Guarde este número.</p>
  ${req.session.user ? '<p><a class="btn" href="/minhas-solicitacoes">Acompanhar</a></p>' : '<p>Crie uma conta para acompanhar o andamento: <a href="/cadastro">Criar conta</a></p>'}`));
}));

app.get('/minhas-solicitacoes', needLogin, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM solicitacoes WHERE usuario_id=$1 ORDER BY criado_em DESC', [req.session.user.id]);
  const lista = rows.length ? rows.map(s => `<article class="item"><h3>${esc(s.categoria)} <span class="tag">${esc(s.status)}</span></h3>
<p class="meta">${s.protocolo} · ${fmt(s.criado_em)} · ${esc(s.endereco)}, ${esc(s.bairro)}</p><p>${esc(s.descricao)}</p>
${s.resposta_equipe ? `<p><strong>Resposta da equipe:</strong> ${esc(s.resposta_equipe)}</p>` : ''}
${s.status === 'Concluída' && !s.feedback_cidadao ? `<form method="post" action="/feedback/${s.id}" class="form"><label>Como foi o atendimento?<textarea name="feedback" rows="2" maxlength="1000" required></textarea></label><button class="btn small">Enviar feedback</button></form>` : ''}
${s.feedback_cidadao ? `<p><strong>Seu feedback:</strong> ${esc(s.feedback_cidadao)}</p>` : ''}</article>`).join('') : '<p>Você ainda não registrou solicitações. <a href="/solicitar">Registrar agora</a></p>';
  res.send(page(res, 'Minhas solicitações', `<h1>Minhas solicitações</h1>${lista}
<details class="danger"><summary>Excluir minha conta e meus dados</summary><p>Sua conta será apagada e suas solicitações serão desvinculadas e anonimizadas.</p>
<form method="post" action="/minha-conta/excluir"><button class="btn danger-btn">Excluir definitivamente</button></form></details>`));
}));
app.post('/feedback/:id', needLogin, wrap(async (req, res) => {
  await pool.query('UPDATE solicitacoes SET feedback_cidadao=$1, atualizado_em=now() WHERE id=$2 AND usuario_id=$3', [String(req.body.feedback || '').slice(0, 1000), req.params.id, req.session.user.id]);
  res.redirect('/minhas-solicitacoes');
}));
app.post('/minha-conta/excluir', needLogin, wrap(async (req, res) => {
  const id = req.session.user.id;
  await pool.query(`UPDATE solicitacoes SET nome='Anonimizado', endereco='Removido', telefone='0', email=NULL, atualizado_em=now() WHERE usuario_id=$1`, [id]);
  await pool.query('DELETE FROM usuarios WHERE id=$1', [id]);
  req.session.destroy(() => res.redirect('/'));
}));

// ---------- admin ----------
app.get('/admin', needAdmin, wrap(async (req, res) => {
  const f = STATUS.includes(req.query.status) ? req.query.status : null;
  const { rows } = await pool.query(`SELECT * FROM solicitacoes ${f ? 'WHERE status=$1' : ''} ORDER BY criado_em DESC LIMIT 200`, f ? [f] : []);
  const filtros = `<p class="filtros"><a href="/admin">Todas</a>${STATUS.map(s => `<a href="/admin?status=${encodeURIComponent(s)}">${s}</a>`).join('')}</p>`;
  const itens = rows.map(s => `<article class="item"><h3>${s.protocolo} · ${esc(s.categoria)} <span class="tag">${esc(s.status)}</span></h3>
<p class="meta">${fmt(s.criado_em)} · ${esc(s.nome)} · <a href="https://wa.me/55${s.telefone}">${esc(s.telefone)}</a>${s.email ? ' · ' + esc(s.email) : ''}</p>
<p>${esc(s.endereco)}, ${esc(s.bairro)} – ${esc(s.cidade)}</p><p>${esc(s.descricao)}</p>
${s.feedback_cidadao ? `<p><strong>Feedback do cidadão:</strong> ${esc(s.feedback_cidadao)}</p>` : ''}
<form method="post" action="/admin/${s.id}" class="form inline"><select name="status">${STATUS.map(x => `<option ${x === s.status ? 'selected' : ''}>${x}</option>`).join('')}</select>
<input name="resposta" placeholder="Resposta ao cidadão" maxlength="1000" value="${esc(s.resposta_equipe)}"><button class="btn small">Salvar</button></form></article>`).join('') || '<p>Nenhuma solicitação.</p>';
  res.send(page(res, 'Painel', `<h1>Painel da equipe</h1>${filtros}${itens}`));
}));
app.post('/admin/:id', needAdmin, wrap(async (req, res) => {
  if (!STATUS.includes(req.body.status)) return res.redirect('/admin');
  await pool.query('UPDATE solicitacoes SET status=$1, resposta_equipe=$2, atualizado_em=now() WHERE id=$3', [req.body.status, String(req.body.resposta || '').slice(0, 1000) || null, req.params.id]);
  res.redirect('back');
}));

// ---------- inicialização ----------
(async () => {
  await pool.query(fs.readFileSync('schema.sql', 'utf8'));
  const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(`INSERT INTO usuarios(nome,email,telefone,senha_hash,papel) VALUES('Administrador',$1,'0000000000',$2,'admin') ON CONFLICT (email) DO NOTHING`, [ADMIN_EMAIL.toLowerCase(), hash]);
  }
  app.listen(process.env.PORT || 3000, () => console.log('Servidor no ar'));
})().catch(e => { console.error(e); process.exit(1); });

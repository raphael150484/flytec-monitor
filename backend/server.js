import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_URL = 'http://new.i-elitech.com';
const {
  ELITECH_KEY_ID,
  ELITECH_KEY_SECRET,
  ELITECH_USER,
  ELITECH_PASS,
  JWT_SECRET
} = process.env;

const JWT_SECRET_KEY = JWT_SECRET || 'chave-secreta-flytec-trocar-no-env';

// Lista de todos os aparelhos disponíveis
const TODOS_DISPOSITIVOS = [
  { guid: '80053908237226281272', nome: 'Equipamento 1' },
  { guid: '80544818780251830930', nome: 'Equipamento 2' }
];

let accessToken = null;
const USERS_FILE = path.join(__dirname, 'users.json');

// ─────────────────────────────────────────
// Usuários
// ─────────────────────────────────────────
function carregarUsuarios() {
  try {
    if (!fs.existsSync(USERS_FILE)) return [];
    const json = JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
    return Array.isArray(json) ? json : [];
  } catch (e) {
    console.error('Erro ao carregar usuários:', e.message);
    return [];
  }
}

function salvarUsuarios(usuarios) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(usuarios, null, 2), 'utf-8');
}

function garantirAdminInicial() {
  const usuarios = carregarUsuarios();
  if (!usuarios.find(u => u.username === 'admin')) {
    const senhaHash = bcrypt.hashSync('admin123', 10);
    usuarios.push({
      id: 1,
      username: 'admin',
      passwordHash: senhaHash,
      role: 'admin',
      dispositivos: TODOS_DISPOSITIVOS.map(d => d.guid) // admin vê tudo
    });
    salvarUsuarios(usuarios);
    console.log('Admin padrão criado: admin / admin123');
  }
}

// ─────────────────────────────────────────
// JWT
// ─────────────────────────────────────────
function gerarToken(usuario) {
  return jwt.sign(
    { id: usuario.id, username: usuario.username, role: usuario.role },
    JWT_SECRET_KEY,
    { expiresIn: '7d' }
  );
}

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Token não fornecido' });
  const partes = authHeader.split(' ');
  if (partes.length !== 2 || partes[0] !== 'Bearer') {
    return res.status(401).json({ success: false, error: 'Formato de token inválido' });
  }
  try {
    req.user = jwt.verify(partes[1], JWT_SECRET_KEY);
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: 'Token inválido ou expirado' });
  }
}

function apenasAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Acesso permitido apenas para admin' });
  }
  next();
}

// ─────────────────────────────────────────
// Elitech
// ─────────────────────────────────────────
async function getElitechToken() {
  console.log('Obtendo token Elitech...');
  const { data } = await axios.post(
    `${BASE_URL}/api/data-api/elitechAccess/getToken`,
    { keyId: ELITECH_KEY_ID, keySecret: ELITECH_KEY_SECRET, userName: ELITECH_USER, password: ELITECH_PASS }
  );
  if (String(data.code) !== '0') throw new Error(`Erro token Elitech: ${data.msg || data.message}`);
  accessToken = data.data;
  console.log('Token Elitech obtido!');
}

async function callElitech(endpoint, body, retry = true) {
  if (!accessToken) await getElitechToken();
  try {
    const { data } = await axios.post(`${BASE_URL}${endpoint}`, body, {
      headers: { Authorization: accessToken, 'Content-Type': 'application/json' }
    });
    return data;
  } catch (err) {
    if (retry && err.response?.status === 401) {
      accessToken = null;
      return callElitech(endpoint, body, false);
    }
    throw err;
  }
}

function formatarDispositivo(device) {
  return {
    deviceGuid:    device.deviceGuid,
    deviceName:    device.deviceName,
    temperatura1:  device.tmp1   || null,
    temperatura2:  device.tmp2   || null,
    temperatura3:  device.tmp3   || null,
    temperatura4:  device.tmp4   || null,
    umidade1:      device.hum1   || null,
    umidade2:      device.hum2   || null,
    luminosidade:  device.lux1   || null,
    bateria:       device.power  || null,
    sinal:         device.signal || null,
    endereco:      device.address || null,
    emAlarme:      device.alarmState || false,
    emAlerta:      device.warnState  || false,
    ultimaLeitura: device.lastSessionTime
      ? new Date(device.lastSessionTime * 1000).toLocaleString('pt-BR')
      : null
  };
}

// ═════════════════════════════════════════
// ROTAS DE AUTENTICAÇÃO
// ═════════════════════════════════════════

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Preencha usuário e senha' });
  }
  const usuarios = carregarUsuarios();
  const usuario  = usuarios.find(u => u.username === username);
  if (!usuario || !bcrypt.compareSync(password, usuario.passwordHash)) {
    return res.status(401).json({ success: false, error: 'Usuário ou senha inválidos' });
  }
  const token = gerarToken(usuario);
  res.json({
    success: true,
    token,
    user: {
      id: usuario.id,
      username: usuario.username,
      role: usuario.role,
      dispositivos: usuario.dispositivos || []
    }
  });
});

// Listar dispositivos disponíveis (para o admin usar no cadastro)
app.get('/api/dispositivos-disponiveis', autenticarToken, apenasAdmin, (req, res) => {
  res.json({ success: true, data: TODOS_DISPOSITIVOS });
});

// Listar usuários (admin)
app.get('/api/usuarios', autenticarToken, apenasAdmin, (req, res) => {
  const lista = carregarUsuarios().map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    dispositivos: u.dispositivos || []
  }));
  res.json({ success: true, data: lista });
});

// Cadastrar usuário (admin)
app.post('/api/usuarios', autenticarToken, apenasAdmin, (req, res) => {
  const { username, password, role, dispositivos } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Usuário e senha são obrigatórios' });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Senha precisa ter pelo menos 6 caracteres' });
  }

  const usuarios = carregarUsuarios();
  if (usuarios.find(u => u.username === username)) {
    return res.status(400).json({ success: false, error: 'Usuário já existe' });
  }

  const novoId    = usuarios.length ? Math.max(...usuarios.map(u => u.id)) + 1 : 1;
  const senhaHash = bcrypt.hashSync(password, 10);

  // Se for admin, libera tudo automaticamente
  const dispositivosLiberados = role === 'admin'
    ? TODOS_DISPOSITIVOS.map(d => d.guid)
    : (Array.isArray(dispositivos) ? dispositivos : []);

  const novo = {
    id: novoId,
    username,
    passwordHash: senhaHash,
    role: role === 'admin' ? 'admin' : 'monitor',
    dispositivos: dispositivosLiberados
  };

  usuarios.push(novo);
  salvarUsuarios(usuarios);

  console.log(`Usuário "${username}" (${novo.role}) cadastrado. Dispositivos: ${dispositivosLiberados}`);
  res.json({ success: true, user: { id: novo.id, username: novo.username, role: novo.role, dispositivos: novo.dispositivos } });
});

// Editar permissões de dispositivos de um usuário (admin)
app.put('/api/usuarios/:id/dispositivos', autenticarToken, apenasAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { dispositivos } = req.body;

  if (!Array.isArray(dispositivos)) {
    return res.status(400).json({ success: false, error: 'Lista de dispositivos inválida' });
  }

  const usuarios = carregarUsuarios();
  const usuario  = usuarios.find(u => u.id === id);

  if (!usuario) {
    return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
  }

  usuario.dispositivos = dispositivos;
  salvarUsuarios(usuarios);

  console.log(`Dispositivos de "${usuario.username}" atualizados: ${dispositivos}`);
  res.json({ success: true, message: 'Permissões atualizadas com sucesso' });
});

// Remover usuário (admin)
app.delete('/api/usuarios/:id', autenticarToken, apenasAdmin, (req, res) => {
  const id = Number(req.params.id);
  let usuarios = carregarUsuarios();
  const alvo   = usuarios.find(u => u.id === id);

  if (!alvo) return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
  if (alvo.username === req.user.username) {
    return res.status(400).json({ success: false, error: 'Você não pode remover a si mesmo' });
  }

  usuarios = usuarios.filter(u => u.id !== id);
  salvarUsuarios(usuarios);

  console.log(`Usuário "${alvo.username}" removido por ${req.user.username}`);
  res.json({ success: true, message: 'Usuário removido com sucesso' });
});

// Trocar senha (qualquer usuário logado)
app.post('/api/trocar-senha', autenticarToken, (req, res) => {
  const { senhaAtual, novaSenha } = req.body;

  if (!senhaAtual || !novaSenha) {
    return res.status(400).json({ success: false, error: 'Preencha todos os campos' });
  }
  if (novaSenha.length < 6) {
    return res.status(400).json({ success: false, error: 'Nova senha precisa ter pelo menos 6 caracteres' });
  }

  const usuarios = carregarUsuarios();
  const usuario  = usuarios.find(u => u.username === req.user.username);

  if (!usuario) return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
  if (!bcrypt.compareSync(senhaAtual, usuario.passwordHash)) {
    return res.status(401).json({ success: false, error: 'Senha atual incorreta' });
  }

  usuario.passwordHash = bcrypt.hashSync(novaSenha, 10);
  salvarUsuarios(usuarios);

  console.log(`Senha alterada para "${req.user.username}"`);
  res.json({ success: true, message: 'Senha alterada com sucesso' });
});

// ═════════════════════════════════════════
// ROTAS ELITECH (protegidas)
// ═════════════════════════════════════════

app.get('/api/status', autenticarToken, (req, res) => {
  res.json({ status: 'ok', user: req.user });
});

// Tempo real — filtra por dispositivos liberados do usuário
app.get('/api/realtime', autenticarToken, async (req, res) => {
  try {
    const usuarios = carregarUsuarios();
    const usuario  = usuarios.find(u => u.username === req.user.username);

    // Admin vê tudo, monitor só os liberados
    let guidsPermitidos;
    if (req.user.role === 'admin') {
      guidsPermitidos = TODOS_DISPOSITIVOS.map(d => d.guid);
    } else {
      guidsPermitidos = usuario?.dispositivos || [];
    }

    if (!guidsPermitidos.length) {
      return res.json({ success: true, total: 0, data: [] });
    }

    console.log(`Buscando tempo real para: ${guidsPermitidos} (usuário: ${req.user.username})`);

    const realtimeResp = await callElitech(
      '/api/data-api/elitechAccess/getRealTimeData',
      { keyId: ELITECH_KEY_ID, keySecret: ELITECH_KEY_SECRET, deviceGuids: guidsPermitidos }
    );

    console.log('Resposta getRealTimeData:', JSON.stringify(realtimeResp));

    if (String(realtimeResp.code) === '5110') {
      return res.status(429).json({ success: false, error: 'Limite de chamadas atingido. Aguarde 1 minuto.' });
    }

    // Algum dispositivo sem API — tenta um por um
    if (String(realtimeResp.code) === '5109') {
      console.log('Código 5109: tentando dispositivos um por um...');
      const resultados = [];
      for (const guid of guidsPermitidos) {
        try {
          const r = await callElitech(
            '/api/data-api/elitechAccess/getRealTimeData',
            { keyId: ELITECH_KEY_ID, keySecret: ELITECH_KEY_SECRET, deviceGuids: [guid] }
          );
          if (String(r.code) === '0' && Array.isArray(r.data)) {
            resultados.push(...r.data.map(d => formatarDispositivo(d)));
          }
        } catch (e) {
          console.error(`Erro no dispositivo ${guid}:`, e.message);
        }
      }
      return res.json({ success: true, total: resultados.length, data: resultados });
    }

    if (String(realtimeResp.code) !== '0') {
      return res.status(500).json({
        success: false,
        error: `Erro Elitech (código ${realtimeResp.code}): ${realtimeResp.msg || realtimeResp.message || 'sem mensagem'}`
      });
    }

    if (!Array.isArray(realtimeResp.data)) {
      return res.status(500).json({ success: false, error: 'Formato de resposta inesperado.' });
    }

    const resultado = realtimeResp.data.map(d => formatarDispositivo(d));
    res.json({ success: true, total: resultado.length, data: resultado });

  } catch (err) {
    console.error('Erro em /api/realtime:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Tempo real — GUID específico
app.get('/api/realtime/:guid', autenticarToken, async (req, res) => {
  try {
    const guid     = req.params.guid;
    const usuarios = carregarUsuarios();
    const usuario  = usuarios.find(u => u.username === req.user.username);

    // Checa permissão
    if (req.user.role !== 'admin' && !(usuario?.dispositivos || []).includes(guid)) {
      return res.status(403).json({ success: false, error: 'Sem permissão para este dispositivo' });
    }

    const realtimeResp = await callElitech(
      '/api/data-api/elitechAccess/getRealTimeData',
      { keyId: ELITECH_KEY_ID, keySecret: ELITECH_KEY_SECRET, deviceGuids: [guid] }
    );

    if (String(realtimeResp.code) !== '0') {
      return res.status(500).json({ success: false, error: `Erro Elitech (${realtimeResp.code})` });
    }

    res.json({ success: true, data: realtimeResp.data.map(d => formatarDispositivo(d)) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Histórico
app.get('/api/historico/:guid', autenticarToken, async (req, res) => {
  try {
    const { guid } = req.params;
    const usuarios = carregarUsuarios();
    const usuario  = usuarios.find(u => u.username === req.user.username);

    if (req.user.role !== 'admin' && !(usuario?.dispositivos || []).includes(guid)) {
      return res.status(403).json({ success: false, error: 'Sem permissão para este dispositivo' });
    }

    const agora     = Math.floor(Date.now() / 1000);
    const startTime = req.query.startTime ? Number(req.query.startTime) : agora - 86400;
    const endTime   = req.query.endTime   ? Number(req.query.endTime)   : agora;

    const data = await callElitech(
      '/api/data-api/elitechAccess/getHistoryData',
      { keyId: ELITECH_KEY_ID, keySecret: ELITECH_KEY_SECRET, deviceGuid: guid, startTime, endTime }
    );

    if (String(data.code) !== '0') {
      return res.status(500).json({ success: false, error: `Erro Elitech (${data.code})` });
    }

    const historico = (data.data || []).map(r => ({
      deviceGuid:   r.deviceGuid,
      temperatura1: r.tmp1   || null,
      temperatura2: r.tmp2   || null,
      umidade1:     r.hum1   || null,
      bateria:      r.power  || null,
      sinal:        r.signal || null,
      horario:      r.monitorTime
        ? new Date(r.monitorTime * 1000).toLocaleString('pt-BR')
        : null
    }));

    res.json({ success: true, total: historico.length, data: historico });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────
// Sobe o servidor
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
garantirAdminInicial();
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log('Login padrão: admin / admin123');
});
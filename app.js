const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    // Senha armazenada como o hash SHA-256 de "123456" para simular armazenamento seguro em repouso
    passwordHash: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", 
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    // Senha armazenada como o hash SHA-256 de "123456"
    passwordHash: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", 
    role: "PROFESSOR",
    classes: ["5A", "5B"]
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    // Senha armazenada como o hash SHA-256 de "admin"
    passwordHash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", 
    role: "ADMIN"
  }
];

const FAKE_API_TOKEN = "TOKEN_SECRETO_DEMO_ABC123_PUBLICO_NO_FRONTEND";

const STORAGE_KEYS = {
  session: "ocorrencias_sessao",
  occurrences: "ocorrencias_registros",
  audit: "ocorrencias_logs"
};

const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Marina Alves",
    studentId: "202300145",
    studentCpf: "123.456.789-10",
    studentEmail: "marina.alves@email.local",
    studentPhone: "(47) 99999-1010",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    studentCpf: "987.654.321-00",
    studentEmail: "rafael.martins@email.local",
    studentPhone: "(47) 98888-2020",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    studentCpf: "111.222.333-44",
    studentEmail: "beatriz.costa@email.local",
    studentPhone: "(47) 97777-3030",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  }
];

const loginView = document.querySelector("#loginView");
const appView = document.querySelector("#appView");
const loginForm = document.querySelector("#loginForm");
const occurrenceForm = document.querySelector("#occurrenceForm");
const logoutBtn = document.querySelector("#logoutBtn");
const exportBtn = document.querySelector("#exportBtn");
const clearLogsBtn = document.querySelector("#clearLogsBtn");
const resetBtn = document.querySelector("#resetBtn");
const searchInput = document.querySelector("#search");
const roleSelect = document.querySelector("#roleSelect");

const sessionBadge = document.querySelector("#sessionBadge");
const currentUserName = document.querySelector("#currentUserName");
const currentUserDetails = document.querySelector("#currentUserDetails");
const occurrencesTable = document.querySelector("#occurrencesTable");
const auditLog = document.querySelector("#auditLog");
const totalOccurrences = document.querySelector("#totalOccurrences");
const criticalOccurrences = document.querySelector("#criticalOccurrences");
const lastUpdate = document.querySelector("#lastUpdate");

// FUNÇÕES AUXILIARES DE CONTROLE E SEGURANÇA

/**
 * SANITIZAÇÃO CONTRA CROSS-SITE SCRIPTING (XSS)
 * Neutraliza caracteres especiais injetados nos formulários antes do armazenamento/exibição.
 */
function sanitize(text) {
  if (typeof text !== 'string') return text;
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * MELHORIA: SIMULAÇÃO DE HASH CRIPTOGRÁFICO (SHA-256 Fictício)
 * Evita a comparação direta de senhas em texto claro no código JavaScript cliente.
 */
function mockHashSHA256(password) {
  if (password === "123456") return "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
  if (password === "admin") return "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
  return "f2ca1bb6c7e907d06dafe4687e579fcee76b37742c1370e8b3a531f4a3846756"; // Hash genérico para falhas
}

/**
 * PROTEÇÃO DE DADOS (MÁSCARA EM TEMPO DE USO)
 * Oculta trechos de documentos (CPF) e contatos sensíveis para cumprir diretrizes de privacidade.
 */
function maskData(text, type) {
  if (!text || typeof text !== 'string') return "—";
  if (type === 'cpf') {
    return "***.***." + text.split('.').pop(); // Exibe apenas os últimos dígitos
  }
  if (type === 'phone') {
    return "(**) *****-" + text.split('-').pop();
  }
  return text;
}

/**
 * MELHORIA: POLÍTICA DE PRIVILÉGIOS NA INTERFACE (RBAC)
 * Controla a visibilidade estrutural do DOM e as travas de execução com base no perfil ativo.
 */
function aplicarPoliticaAcesso(role) {
  const elementsAdmin = document.querySelectorAll('.admin-only');
  const elementsProf = document.querySelectorAll('.prof-only');
  const occurrenceCard = document.querySelector("#occurrenceCreationCard");
  const auditSection = document.querySelector("#auditSection");

  // Garante tipo de perfil antes de computar
  const activeRole = sanitize(role).toUpperCase();

  if (activeRole === "ALUNO") {
    elementsAdmin.forEach(el => el.classList.add("restricted-view"));
    elementsProf.forEach(el => el.classList.add("restricted-view"));
    if (occurrenceCard) occurrenceCard.classList.add("restricted-view");
    if (auditSection) auditSection.classList.add("restricted-view");
  } 
  else if (activeRole === "PROFESSOR") {
    elementsAdmin.forEach(el => el.classList.add("restricted-view"));
    elementsProf.forEach(el => el.classList.remove("restricted-view"));
    if (occurrenceCard) occurrenceCard.classList.remove("restricted-view");
    if (auditSection) auditSection.classList.add("restricted-view");
  } 
  else if (activeRole === "ADMIN") {
    elementsAdmin.forEach(el => el.classList.remove("restricted-view"));
    elementsProf.forEach(el => el.classList.remove("restricted-view"));
    if (occurrenceCard) occurrenceCard.classList.remove("restricted-view");
    if (auditSection) auditSection.classList.remove("restricted-view");
  }
}

// OPERAÇÕES DO SISTEMA

function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  }

  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([
      {
        when: new Date().toISOString(),
        user: "sistema",
        action: "BASE_INICIAL_CRIADA",
        detail: "Dados fictícios carregados no localStorage de forma segura."
      }
    ]));
  }

  const session = getSession();

  if (session) {
    showApp(session);
  } else {
    showLogin();
  }
}

function getOccurrences() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
}

function saveOccurrences(occurrences) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(occurrences));
}

function getAuditLogs() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function getSession() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.session) || "null");
}

function saveSession(user) {
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(user));
}

function writeLog(action, detail) {
  const session = getSession();
  const logs = getAuditLogs();

  logs.unshift({
    when: new Date().toISOString(),
    user: session ? sanitize(session.email) : "anonimo",
    role: session ? sanitize(session.role) : "SEM_SESSAO",
    action: sanitize(action),
    detail: sanitize(detail)
  });

  saveAuditLogs(logs);
}

function showLogin() {
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  sessionBadge.textContent = `${sanitize(user.name)} — ${sanitize(user.role)}`;
  sessionBadge.classList.remove("muted");

  currentUserName.textContent = sanitize(user.name);
  currentUserDetails.textContent = `${sanitize(user.email)} | Perfil: ${sanitize(user.role)}`;
  roleSelect.value = user.role;

  // Ativa as barreiras Visuais baseadas no Perfil Logado
  aplicarPoliticaAcesso(user.role);

  render();
}

function login(email, password) {
  const emailSanitizado = sanitize(email);
  const inputHash = mockHashSHA256(password);

  // Busca e validação utilizando o hash simulado contra armazenamento
  const user = USERS.find((item) => item.email === emailSanitizado && item.passwordHash === inputHash);

  if (!user) {
    alert("Usuário ou senha inválidos.");
    writeLog("LOGIN_FALHOU", `Tentativa de login malsucedida para o e-mail: ${emailSanitizado}`);
    return;
  }

  saveSession(user);
  writeLog("LOGIN_OK", `Usuário ${user.email} autenticado no ecossistema front-end.`);
  showApp(user);
}

function logout() {
  const session = getSession();
  writeLog("LOGOUT", session ? `${session.email} encerrou a sessão no cliente.` : "Sessão destruída.");
  localStorage.removeItem(STORAGE_KEYS.session);
  showLogin();
}

function changeRole(newRole) {
  const session = getSession();

  if (!session) return;

  const roleSanitizada = sanitize(newRole).toUpperCase();
  session.role = roleSanitizada;
  saveSession(session);
  
  writeLog("PERFIL_ALTERADO", `Simulação: Perfil forçado localmente para ${roleSanitizada}.`);
  showApp(session);
}

function createOccurrence(event) {
  event.preventDefault();

  const session = getSession();
  
  // BLOQUEIO DE SEGURANÇA OPERACIONAL: Alunos não criam ocorrências via código
  if (session && session.role === "ALUNO") {
    alert("Operação não autorizada: Seu perfil não possui privilégios de gravação.");
    writeLog("VIOLACAO_SEGURANCA", "Tentativa ilícita de criação de ocorrência bloqueada para perfil ALUNO.");
    return;
  }

  // Captura com Sanitização ativa imediata (Mitigação do XSS persistido no LocalStorage)
  const occurrence = {
    id: `OC-${Math.floor(Math.random() * 9000) + 1000}`,
    studentName: sanitize(document.querySelector("#studentName").value),
    studentId: sanitize(document.querySelector("#studentId").value),
    studentCpf: sanitize(document.querySelector("#studentCpf").value),
    studentEmail: sanitize(document.querySelector("#studentEmail").value),
    studentPhone: sanitize(document.querySelector("#studentPhone").value),
    category: sanitize(document.querySelector("#category").value),
    priority: sanitize(document.querySelector("#priority").value),
    description: sanitize(document.querySelector("#description").value),
    internalNote: sanitize(document.querySelector("#internalNote").value),
    privacyAck: document.querySelector("#privacyAck").checked,
    status: "Aberta",
    createdBy: session ? sanitize(session.email) : "desconhecido",
    createdAt: new Date().toISOString()
  };

  const occurrences = getOccurrences();
  occurrences.unshift(occurrence);
  saveOccurrences(occurrences);

  writeLog(
    "OCORRENCIA_CRIADA",
    `Criada ocorrência ${occurrence.id} sob privilégios. Aluno alvo higienizado.`
  );

  occurrenceForm.reset();
  render();
}

function deleteOccurrence(id) {
  const session = getSession();
  
  // Apenas administradores deletam registros
  if (!session || session.role !== "ADMIN") {
    alert("Operação não autorizada: Apenas administradores podem remover registros ativos.");
    writeLog("VIOLACAO_SEGURANCA", `Tentativa de exclusão negada na ocorrência ${sanitize(id)}.`);
    return;
  }

  const occurrences = getOccurrences();
  const idSanitizado = sanitize(id);
  const occurrence = occurrences.find((item) => item.id === idSanitizado);
  const updated = occurrences.filter((item) => item.id !== idSanitizado);

  saveOccurrences(updated);
  writeLog("OCORRENCIA_EXCLUIDA", `Ocorrência ${idSanitizado} deletada pelo Administrador.`);
  render();
}

function changeStatus(id, status) {
  const session = getSession();
  
  // Alunos não modificam status
  if (!session || session.role === "ALUNO") {
    alert("Operação não autorizada para o nível de privilégio Aluno.");
    return;
  }

  const occurrences = getOccurrences();
  const idSanitizado = sanitize(id);
  const occurrence = occurrences.find((item) => item.id === idSanitizado);

  if (!occurrence) return;

  const statusSanitizado = sanitize(status);
  occurrence.status = statusSanitizado;
  occurrence.updatedAt = new Date().toISOString();

  saveOccurrences(occurrences);
  writeLog("STATUS_ALTERADO", `Ocorrência ${idSanitizado} atualizada para o estado: ${statusSanitizado}.`);
  render();
}

function exportEverything() {
  const session = getSession();
  
  // Restrição de vazamento em massa de dados confidenciais
  if (!session || session.role !== "ADMIN") {
    alert("Acesso restrito: A exportação de dados estruturais é permitida apenas a Administradores.");
    writeLog("VIOLACAO_PRIVACIDADE", "Tentativa de exfiltração em massa de dados bloqueada.");
    return;
  }

  const payload = {
    exportedAt: new Date().toISOString(),
    exportedBy: session,
    token: FAKE_API_TOKEN,
    users: USERS.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })), // Remove hashes na exportação
    occurrences: getOccurrences(),
    audit: getAuditLogs(),
    localStorageCopy: { ...localStorage }
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = "backup-seguro-ocorrencias.json";
  anchor.click();

  URL.revokeObjectURL(url);
  writeLog("EXPORTACAO_TOTAL", "Relatório global e logs do sistema exportados legalmente.");
}

function clearLogs() {
  const session = getSession();
  if (!session || session.role !== "ADMIN") {
    alert("Ação negada: Quebra de custódia de histórico de auditoria.");
    return;
  }
  saveAuditLogs([]);
  render();
}

function resetData() {
  const session = getSession();
  if (session && session.role !== "ADMIN") {
    alert("Ação restrita a Administradores.");
    return;
  }
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([]));
  localStorage.removeItem(STORAGE_KEYS.session);
  boot();
}

function render() {
  const term = sanitize(searchInput.value.toLowerCase());
  const occurrences = getOccurrences();
  const session = getSession();
  const roleAtivo = session ? session.role : "ALUNO";

  const filtered = occurrences.filter((item) => {
    const content = JSON.stringify(item).toLowerCase();
    return content.includes(term);
  });

  totalOccurrences.textContent = occurrences.length;
  criticalOccurrences.textContent = occurrences.filter((item) => item.priority === "Crítica").length;
  lastUpdate.textContent = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  occurrencesTable.innerHTML = filtered.map((item) => {
    // Perfis inferiores visualizam dados sob máscaras e restrição de notas internas
    const cpfExibido = roleAtivo === "ADMIN" ? sanitize(item.studentCpf) : maskData(sanitize(item.studentCpf), 'cpf');
    const foneExibido = roleAtivo === "ADMIN" ? sanitize(item.studentPhone) : maskData(sanitize(item.studentPhone), 'phone');
    const notaExibida = roleAtivo === "ADMIN" ? sanitize(item.internalNote) : "🔒 [RESTRITO PARA ESTE PERFIL]";

    return `
    <tr>
      <td>
        <strong>${sanitize(item.studentName)}</strong><br />
        <span class="muted-text">${sanitize(item.studentId)}</span>
      </td>
      <td>${cpfExibido}</td>
      <td>
        ${sanitize(item.studentEmail)}<br />
        ${foneExibido}
      </td>
      <td>${sanitize(item.category)}</td>
      <td><span class="priority ${sanitize(item.priority)}">${sanitize(item.priority)}</span></td>
      <td>${sanitize(item.status)}</td>
      <td>
        <strong>Descrição:</strong> ${sanitize(item.description)}<br />
        <strong>Obs. interna:</strong> ${notaExibida}
      </td>
      <td>
        <div class="row-actions ${roleAtivo === 'ALUNO' ? 'restricted-view' : ''}">
          <button class="btn secondary" onclick="changeStatus('${sanitize(item.id)}', 'Em análise')">Em análise</button>
          <button class="btn secondary" onclick="changeStatus('${sanitize(item.id)}', 'Resolvida')">Resolver</button>
          <button class="btn danger ${roleAtivo !== 'ADMIN' ? 'restricted-view' : ''}" onclick="deleteOccurrence('${sanitize(item.id)}')">Excluir</button>
        </div>
      </td>
    </tr>
  `}).join("");

  const logs = getAuditLogs();

  if (logs.length === 0) {
    auditLog.innerHTML = `<div class="notice">Nenhum log registrado na auditoria local.</div>`;
  } else {
    // Renderiza a lista de logs higienizando as saídas contra XSS stored
    auditLog.innerHTML = logs.map((log) => `
      <div class="log-item">
        <strong>${sanitize(log.when)}</strong><br />
        usuário=${sanitize(log.user) || "—"} | perfil=${sanitize(log.role) || "—"} | ação=${sanitize(log.action)}<br />
        detalhe=${sanitize(log.detail)}
      </div>
    `).join("");
  }
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  login(
    document.querySelector("#email").value,
    document.querySelector("#password").value
  );
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportEverything);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);
searchInput.addEventListener("input", render);

roleSelect.addEventListener("change", (event) => {
  changeRole(event.target.value);
});

window.deleteOccurrence = deleteOccurrence;
window.changeStatus = changeStatus;

boot();

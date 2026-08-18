// Mock seguro: gera e manipula payloads fictícios sem enviar nada a dispositivos.

const mockPayloads = [
  "mock_payload=1&note=teste",
  "mock_payload=2&note=demo",
  "mock_payload=3&note=integration"
];

const mockSlopkit = [
  "slop_mock=alpha&cmd=echo",
  "slop_mock=beta&cmd=pulse"
];

const logEl = document.getElementById('log');
const btnPayloads = document.getElementById('btnPayloads');
const btnJailbreak = document.getElementById('btnJailbreak');
const btnAll = document.getElementById('btnAll');
const btnCopy = document.getElementById('btnCopy');
const btnDownload = document.getElementById('btnDownload');
const clearBtn = document.getElementById('clear');

function appendLog(...parts) {
  const now = new Date().toLocaleTimeString();
  logEl.value += `[${now}] ${parts.join(' ')}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function simulateInject(list, label) {
  appendLog(`Iniciando simulação: ${label} com ${list.length} payload(s).`);
  for (const p of list) {
    // processamento local simulado — NÃO enviar
    appendLog("Payload preparado (simulado):", p);
  }
  appendLog(`Simulação ${label} concluída.`);
}

btnPayloads.addEventListener('click', () => simulateInject(mockPayloads, "Inject Payloads"));

btnJailbreak.addEventListener('click', () => {
  // Botão bloqueado por segurança: apenas log e instrução
  appendLog("Ação bloqueada: 'Inject Jailbreak' não está disponível por motivos legais/segurança.");
  appendLog("Use apenas operações autorizadas e legais. Esta UI é um mock que NÃO executa nada em dispositivos.");
});

btnAll.addEventListener('click', () => simulateInject([...mockPayloads, ...mockSlopkit], "Inject All"));

btnCopy.addEventListener('click', async () => {
  const all = [...mockPayloads, ...mockSlopkit].join("\n");
  try {
    await navigator.clipboard.writeText(all);
    appendLog("Payloads fictícios copiados para a área de transferência.");
  } catch (err) {
    appendLog("Falha ao copiar para a área de transferência:", err && err.message ? err.message : err);
  }
});

btnDownload.addEventListener('click', () => {
  const content = [...mockPayloads, ...mockSlopkit].join("\n");
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'payloads_mock.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  appendLog("Arquivo payloads_mock.txt gerado para download (conteúdo fictício).");
});

clearBtn.addEventListener('click', () => logEl.value = "");

// Inicializa
appendLog("UI de mock carregada. Botões simulam ações sem enviar nada a dispositivos.");
'use strict';
const CRYPTO = {
  async getKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },
  async encrypt(data, password) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.getKey(password, 'wealthos_salt_v1');
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
    const buf = new Uint8Array(encrypted);
    const result = new Uint8Array(iv.length + buf.length);
    result.set(iv); result.set(buf, iv.length);
    return btoa(String.fromCharCode(...result));
  },
  async decrypt(ciphertext, password) {
    try {
      const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
      const iv = bytes.slice(0, 12); const data = bytes.slice(12);
      const key = await this.getKey(password, 'wealthos_salt_v1');
      const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
      return JSON.parse(new TextDecoder().decode(dec));
    } catch { return null; }
  }
};

let STATE = { user: null, sessionKey: null, records: { income: [], investment: [], expense: [], saving: [], charge: [] } };
let CHARTS = { overview: null, pie: null };
let FACE_STREAM = null;

document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    clearError();
  });
});

function hashPassword(pw) {
  let hash = 0;
  for (let i = 0; i < pw.length; i++) { hash = ((hash << 5) - hash) + pw.charCodeAt(i); hash |= 0; }
  return hash.toString(16) + pw.length.toString(16);
}

async function loginPassword() {
  const name = document.getElementById('loginName').value.trim();
  const pass = document.getElementById('loginPass').value;
  const pin  = document.getElementById('loginPin').value;
  if (!name) return showError('Please enter your name.');
  if (!pass || pass.length < 6) return showError('Password must be at least 6 characters.');
  if (pin && !/^\d{4}$/.test(pin)) return showError('PIN must be exactly 4 digits.');
  const stored = JSON.parse(localStorage.getItem('wealthos_user') || 'null');
  if (!stored) {
    const userObj = { name, passHash: hashPassword(pass), pinHash: pin ? hashPassword(pin) : null, createdAt: new Date().toISOString() };
    localStorage.setItem('wealthos_user', JSON.stringify(userObj));
    STATE.user = userObj; STATE.sessionKey = pass;
    showToast('Account created! Welcome to WealthOS 🎉', 'success');
    launchApp(name);
  } else {
    if (stored.passHash !== hashPassword(pass)) return showError('Incorrect password.');
    if (stored.pinHash && pin && stored.pinHash !== hashPassword(pin)) return showError('Incorrect PIN.');
    STATE.user = stored; STATE.sessionKey = pass;
    await loadEncryptedData(pass);
    launchApp(stored.name);
  }
}

document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') loginPassword(); });
document.getElementById('loginPin').addEventListener('keydown', e => { if (e.key === 'Enter') loginPassword(); });
function togglePw() { const inp = document.getElementById('loginPass'); inp.type = inp.type === 'password' ? 'text' : 'password'; }

async function startFaceAuth() {
  const stored = JSON.parse(localStorage.getItem('wealthos_user') || 'null');
  if (!stored) return showError('Register with password first!');
  document.getElementById('faceStatus').textContent = 'Loading face models...';
  try {
    await Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri('https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@master/weights'),
      faceapi.nets.faceLandmark68Net.loadFromUri('https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@master/weights'),
      faceapi.nets.faceRecognitionNet.loadFromUri('https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@master/weights')
    ]);
  } catch(e) { document.getElementById('faceStatus').textContent = 'Models failed. Use another method.'; return; }
  try {
    FACE_STREAM = await navigator.mediaDevices.getUserMedia({ video: {} });
    const video = document.getElementById('faceVideo');
    video.srcObject = FACE_STREAM;
    await new Promise(r => video.onloadedmetadata = r);
    document.getElementById('faceStatus').textContent = 'Scanning your face...';
    setTimeout(async () => {
      const detection = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptor();
      if (detection) {
        const storedDesc = JSON.parse(localStorage.getItem('wealthos_face') || 'null');
        if (!storedDesc) {
          localStorage.setItem('wealthos_face', JSON.stringify(Array.from(detection.descriptor)));
          document.getElementById('faceStatus').textContent = 'Face registered! ✓';
          stopCamera(); STATE.user = stored; STATE.sessionKey = stored.passHash;
          await loadEncryptedDataFallback(); launchApp(stored.name);
        } else {
          const dist = faceapi.euclideanDistance(new Float32Array(storedDesc), detection.descriptor);
          if (dist < 0.5) {
            document.getElementById('faceStatus').textContent = 'Face verified ✓';
            stopCamera(); STATE.user = stored; STATE.sessionKey = stored.passHash;
            await loadEncryptedDataFallback(); launchApp(stored.name);
          } else { document.getElementById('faceStatus').textContent = 'Face not recognized. Try again.'; stopCamera(); }
        }
      } else { document.getElementById('faceStatus').textContent = 'No face detected. Try again.'; stopCamera(); }
    }, 3000);
  } catch(err) { document.getElementById('faceStatus').textContent = 'Camera access denied.'; }
}

function stopCamera() { if (FACE_STREAM) { FACE_STREAM.getTracks().forEach(t => t.stop()); FACE_STREAM = null; } }

async function startBioAuth() {
  const stored = JSON.parse(localStorage.getItem('wealthos_user') || 'null');
  if (!stored) return showError('Register with password first!');
  if (!window.PublicKeyCredential) { document.getElementById('bioStatus').textContent = 'WebAuthn not supported.'; return; }
  document.getElementById('bioStatus').textContent = 'Activating biometric sensor...';
  const storedCred = localStorage.getItem('wealthos_biocred');
  try {
    if (!storedCred) {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = crypto.getRandomValues(new Uint8Array(16));
      const cred = await navigator.credentials.create({ publicKey: { challenge, rp: { name: 'WealthOS', id: window.location.hostname || 'localhost' }, user: { id: userId, name: stored.name, displayName: stored.name }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' }, timeout: 60000 } });
      localStorage.setItem('wealthos_biocred', btoa(String.fromCharCode(...new Uint8Array(cred.rawId))));
      document.getElementById('bioStatus').textContent = 'Biometric registered! ✓';
      STATE.user = stored; STATE.sessionKey = stored.passHash;
      await loadEncryptedDataFallback(); launchApp(stored.name);
    } else {
      const credIdBytes = Uint8Array.from(atob(storedCred), c => c.charCodeAt(0));
      await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: window.location.hostname || 'localhost', allowCredentials: [{ type: 'public-key', id: credIdBytes }], userVerification: 'required', timeout: 60000 } });
      document.getElementById('bioStatus').textContent = 'Biometric verified ✓';
      STATE.user = stored; STATE.sessionKey = stored.passHash;
      await loadEncryptedDataFallback(); launchApp(stored.name);
    }
  } catch(e) { document.getElementById('bioStatus').textContent = e.name === 'NotAllowedError' ? 'Authentication cancelled.' : 'Biometric failed. Try another method.'; }
}

async function saveData() {
  try {
    const encrypted = await CRYPTO.encrypt(STATE.records, STATE.sessionKey);
    localStorage.setItem('wealthos_data_enc', encrypted);
    sessionStorage.setItem('wealthos_session', JSON.stringify(STATE.records));
  } catch(e) { localStorage.setItem('wealthos_data_raw', JSON.stringify(STATE.records)); }
}

async function loadEncryptedData(password) {
  const enc = localStorage.getItem('wealthos_data_enc');
  if (enc) { const data = await CRYPTO.decrypt(enc, password); if (data) { STATE.records = data; return; } }
  loadFallbackData();
}
async function loadEncryptedDataFallback() {
  const enc = localStorage.getItem('wealthos_data_enc');
  if (enc) { const data = await CRYPTO.decrypt(enc, STATE.sessionKey); if (data) { STATE.records = data; return; } }
  loadFallbackData();
}
function loadFallbackData() {
  const raw = localStorage.getItem('wealthos_data_raw');
  if (raw) { try { STATE.records = JSON.parse(raw); } catch {} }
  const session = sessionStorage.getItem('wealthos_session');
  if (session) { try { STATE.records = JSON.parse(session); } catch {} }
}

function exportData() {
  const blob = new Blob([JSON.stringify({ app: 'WealthOS', version: '1.0', exportDate: new Date().toISOString(), owner: STATE.user?.name, records: STATE.records }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url;
  a.download = `wealthos_backup_${new Date().toISOString().split('T')[0]}.json`;
  a.click(); URL.revokeObjectURL(url);
  showToast('Data exported successfully!', 'success');
}
function importData(event) {
  const file = event.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = async e => {
    try {
      const data = JSON.parse(e.target.result);
      if (data.records) { STATE.records = data.records; await saveData(); renderAll(); showToast('Data imported successfully!', 'success'); }
    } catch { showToast('Invalid file format!', 'error'); }
  };
  reader.readAsText(file); event.target.value = '';
}

function launchApp(name) {
  stopCamera();
  document.getElementById('loginScreen').classList.remove('active');
  document.getElementById('appScreen').classList.add('active');
  document.getElementById('displayName').textContent = name;
  document.getElementById('avatarEl').textContent = name.charAt(0).toUpperCase();
  document.getElementById('dashDate').textContent = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  renderAll();
}
function logout() {
  if (!confirm('Lock the app?')) return;
  stopCamera(); STATE.user = null; STATE.sessionKey = null;
  STATE.records = { income: [], investment: [], expense: [], saving: [], charge: [] };
  document.getElementById('appScreen').classList.remove('active');
  document.getElementById('loginScreen').classList.add('active');
  Object.values(CHARTS).forEach(c => c && c.destroy()); CHARTS = { overview: null, pie: null };
}

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault(); const page = link.dataset.page;
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    link.classList.add('active');
    document.getElementById(`page-${page}`).classList.add('active');
    if (page === 'dashboard') renderDashboard();
    if (page === 'reports') renderReports();
    if (window.innerWidth <= 768) toggleSidebar();
  });
});
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

const CATEGORIES = {
  income: ['Salary','Freelance','Business Income','Rental Income','Dividend','Bonus','Other Income'],
  investment: ['Stocks','Crypto','Real Estate','Mutual Fund','Gold','Bonds','Business','FD/Savings'],
  expense: ['Food','Transport','Shopping','Entertainment','Health','Education','Bills','Other'],
  saving: ['Emergency Fund','Vacation','Car','Home','Education','Retirement','Custom'],
  charge: ['Electricity','Gas','Internet','Phone','Rent','Insurance','Subscription','Loan EMI']
};
const ICONS = { income: '💰', investment: '📈', expense: '💸', saving: '🏦', charge: '🧾' };

function openModal(type, editId = null) {
  const overlay = document.getElementById('modalOverlay');
  const labels = { income: 'Income', investment: 'Investment', expense: 'Expense', saving: 'Saving Goal', charge: 'Monthly Charge' };
  document.getElementById('modalTitle').textContent = (editId ? 'Edit' : 'Add') + ' ' + labels[type];
  let existing = editId ? STATE.records[type].find(r => r.id === editId) : null;
  const cats = CATEGORIES[type].map(c => `<option value="${c}" ${existing?.category === c ? 'selected' : ''}>${c}</option>`).join('');
  document.getElementById('modalBody').innerHTML = `
    <div class="mform">
      <div class="input-group"><label>Title / Description</label><input type="text" id="mTitle" placeholder="e.g., Monthly Salary" value="${existing?.title || ''}" /></div>
      <div class="input-group"><label>Amount (PKR)</label><input type="number" id="mAmount" placeholder="0.00" min="0" step="0.01" value="${existing?.amount || ''}" /></div>
      <div class="input-group"><label>Category</label><select id="mCategory"><option value="">Select category</option>${cats}</select></div>
      ${type === 'investment' ? `<div class="input-group"><label>Expected Return % (per year)</label><input type="number" id="mReturn" placeholder="e.g., 12" min="0" max="100" value="${existing?.returnPct || ''}" /></div>` : ''}
      ${type === 'saving' ? `<div class="input-group"><label>Target Amount (PKR)</label><input type="number" id="mTarget" placeholder="e.g., 100000" min="0" value="${existing?.target || ''}" /></div>` : ''}
      <div class="input-group"><label>Date</label><input type="date" id="mDate" value="${existing?.date || new Date().toISOString().split('T')[0]}" /></div>
      <div class="input-group"><label>Notes (optional)</label><input type="text" id="mNotes" placeholder="Any notes..." value="${existing?.notes || ''}" /></div>
      <button class="btn-primary" onclick="saveRecord('${type}', ${editId ? `'${editId}'` : null})">${editId ? 'Update Record' : 'Save Record'}</button>
    </div>`;
  overlay.classList.add('open');
  setTimeout(() => document.getElementById('mTitle').focus(), 100);
}
function closeModal(e) {
  if (!e || e.target === document.getElementById('modalOverlay') || e.target.classList.contains('modal-close'))
    document.getElementById('modalOverlay').classList.remove('open');
}
async function saveRecord(type, editId = null) {
  const title = document.getElementById('mTitle').value.trim();
  const amount = parseFloat(document.getElementById('mAmount').value);
  const category = document.getElementById('mCategory').value;
  const date = document.getElementById('mDate').value;
  const notes = document.getElementById('mNotes').value.trim();
  const returnEl = document.getElementById('mReturn');
  const targetEl = document.getElementById('mTarget');
  if (!title) return showToast('Please enter a title.', 'error');
  if (!amount || amount <= 0) return showToast('Enter a valid amount.', 'error');
  if (!category) return showToast('Select a category.', 'error');
  if (!date) return showToast('Select a date.', 'error');
  const record = { id: editId || Date.now().toString(), title, amount, category, date, notes, type };
  if (returnEl) record.returnPct = parseFloat(returnEl.value) || 0;
  if (targetEl) record.target = parseFloat(targetEl.value) || 0;
  if (editId) { const idx = STATE.records[type].findIndex(r => r.id === editId); if (idx > -1) STATE.records[type][idx] = record; }
  else STATE.records[type].unshift(record);
  await saveData(); closeModal(); renderAll();
  showToast(`${editId ? 'Updated' : 'Saved'} successfully! ✓`, 'success');
}
async function deleteRecord(type, id) {
  if (!confirm('Delete this record?')) return;
  STATE.records[type] = STATE.records[type].filter(r => r.id !== id);
  await saveData(); renderAll(); showToast('Record deleted.', 'success');
}

function renderAll() {
  renderDashboard();
  ['income','investment','expense','saving','charge'].forEach(renderList);
}
function fmt(n) { return 'PKR ' + (n || 0).toLocaleString('en-PK', { minimumFractionDigits: 0, maximumFractionDigits: 0 }); }
function fmtShort(n) { if (n >= 1000000) return 'PKR ' + (n/1000000).toFixed(1)+'M'; if (n >= 1000) return 'PKR ' + (n/1000).toFixed(1)+'K'; return 'PKR ' + n; }
function sum(arr) { return arr.reduce((a, r) => a + (r.amount || 0), 0); }

function renderDashboard() {
  const income = sum(STATE.records.income), invest = sum(STATE.records.investment);
  const expense = sum(STATE.records.expense), saving = sum(STATE.records.saving), charges = sum(STATE.records.charge);
  const totalOut = expense + charges, net = income - totalOut;
  document.getElementById('summaryCards').innerHTML = [
    { cls:'income', icon:'💰', label:'Total Income', val:fmtShort(income) },
    { cls:'invest', icon:'📈', label:'Total Investments', val:fmtShort(invest) },
    { cls:'expense', icon:'💸', label:'Total Expenses', val:fmtShort(totalOut) },
    { cls:'saving', icon:'🏦', label:'Total Savings', val:fmtShort(saving) },
    { cls: net>=0?'net':'expense', icon: net>=0?'📊':'⚠️', label:'Net Balance', val:fmtShort(Math.abs(net)), note: net>=0?'Surplus':'Deficit' }
  ].map(c => `<div class="sum-card ${c.cls}"><div class="sum-icon">${c.icon}</div><div class="sum-label">${c.label}</div><div class="sum-amount">${c.val}</div>${c.note?`<div class="sum-change">${c.note}</div>`:''}</div>`).join('');
  renderOverviewChart(income, invest, expense, saving, charges);
  renderPieChart(expense, saving, charges, invest);
  const all = [
    ...STATE.records.income.map(r=>({...r,_type:'income'})),
    ...STATE.records.investment.map(r=>({...r,_type:'investment'})),
    ...STATE.records.expense.map(r=>({...r,_type:'expense'})),
    ...STATE.records.saving.map(r=>({...r,_type:'saving'})),
    ...STATE.records.charge.map(r=>({...r,_type:'charge'}))
  ].sort((a,b)=>new Date(b.date)-new Date(a.date)).slice(0,8);
  const typeClass = { income:'income', investment:'invest', expense:'expense', saving:'saving', charge:'expense' };
  document.getElementById('recentList').innerHTML = all.length === 0
    ? `<div class="empty-state"><div class="empty-icon">📭</div><p>No transactions yet. Start adding records!</p></div>`
    : all.map(r=>`<div class="txn-item"><div class="txn-icon">${ICONS[r._type]}</div><div class="txn-info"><div class="txn-title">${r.title}</div><div class="txn-meta">${r.category} · ${new Date(r.date).toLocaleDateString()}</div></div><div class="txn-amount ${typeClass[r._type]}">${fmt(r.amount)}</div></div>`).join('');
}

function renderOverviewChart(income, invest, expense, saving, charges) {
  const ctx = document.getElementById('overviewChart')?.getContext('2d'); if (!ctx) return;
  if (CHARTS.overview) CHARTS.overview.destroy();
  CHARTS.overview = new Chart(ctx, { type:'bar', data:{ labels:['Income','Investment','Expenses','Savings','Charges'], datasets:[{ data:[income,invest,expense,saving,charges], backgroundColor:['#00d4aa33','#4f7cff33','#ff5c7a33','#f0c06033','#7c5cfc33'], borderColor:['#00d4aa','#4f7cff','#ff5c7a','#f0c060','#7c5cfc'], borderWidth:2, borderRadius:8 }] }, options:{ responsive:true, plugins:{legend:{display:false}}, scales:{ x:{ticks:{color:'#6b7a9a'},grid:{color:'rgba(99,140,255,0.05)'}}, y:{ticks:{color:'#6b7a9a',callback:v=>fmtShort(v)},grid:{color:'rgba(99,140,255,0.05)'}} } } });
}
function renderPieChart(expense, saving, charges, invest) {
  const ctx = document.getElementById('pieChart')?.getContext('2d'); if (!ctx) return;
  if (CHARTS.pie) CHARTS.pie.destroy();
  if (expense+saving+charges+invest === 0) return;
  CHARTS.pie = new Chart(ctx, { type:'doughnut', data:{ labels:['Expenses','Savings','Charges','Investment'], datasets:[{ data:[expense,saving,charges,invest], backgroundColor:['#ff5c7a55','#00d4aa55','#7c5cfc55','#4f7cff55'], borderColor:['#ff5c7a','#00d4aa','#7c5cfc','#4f7cff'], borderWidth:2 }] }, options:{ responsive:true, cutout:'65%', plugins:{ legend:{position:'bottom',labels:{color:'#6b7a9a',padding:12,font:{size:11}}} } } });
}

function renderList(type) {
  const container = document.getElementById(`${type}List`); if (!container) return;
  const records = STATE.records[type];
  const typeClass = { income:'income', investment:'invest', expense:'expense', saving:'saving', charge:'expense' };
  container.innerHTML = !records || records.length === 0
    ? `<div class="empty-state"><div class="empty-icon">${ICONS[type]}</div><p>No ${type} records yet. Click "+ Add" to get started!</p></div>`
    : records.map(r=>`<div class="record-item"><div class="txn-icon">${ICONS[type]}</div><div class="txn-info" style="flex:1"><div class="txn-title">${r.title}</div><div class="txn-meta">${r.category} · ${new Date(r.date).toLocaleDateString()}${r.notes?' · '+r.notes:''}${r.returnPct?' · '+r.returnPct+'% return':''}${r.target?' · Target: '+fmt(r.target):''}</div>${r.target?`<div class="progress-bar"><div class="progress-fill" style="width:${Math.min(100,(r.amount/r.target*100).toFixed(1))}%"></div></div>`:''}</div><div class="txn-amount ${typeClass[type]}">${fmt(r.amount)}</div><div class="record-actions"><button class="btn-edit" onclick="openModal('${type}','${r.id}')">✏</button><button class="btn-del" onclick="deleteRecord('${type}','${r.id}')">🗑</button></div></div>`).join('');
}

function renderReports() {
  const income=sum(STATE.records.income), invest=sum(STATE.records.investment), expense=sum(STATE.records.expense), saving=sum(STATE.records.saving), charges=sum(STATE.records.charge);
  const totalOut=expense+charges, net=income-totalOut;
  function catBreakdown(type) { const map={}; STATE.records[type].forEach(r=>{map[r.category]=(map[r.category]||0)+r.amount;}); return Object.entries(map).sort((a,b)=>b[1]-a[1]); }
  document.getElementById('reportsContent').innerHTML = `
    <div class="report-grid">
      <div class="report-card"><h4>📊 Financial Summary</h4>
        ${[['Total Income',fmt(income),'var(--green)'],['Total Expenses',fmt(totalOut),'var(--red)'],['Net Balance',fmt(net),net>=0?'var(--green)':'var(--red)'],['Investments',fmt(invest),'var(--accent)'],['Savings',fmt(saving),'var(--gold)'],['Monthly Charges',fmt(charges),'var(--text-muted)']].map(([l,v,c])=>`<div class="report-row"><span>${l}</span><span class="report-val" style="color:${c}">${v}</span></div>`).join('')}
      </div>
      <div class="report-card"><h4>📈 Financial Health</h4>
        ${[['Savings Rate',income>0?((saving/income)*100).toFixed(1)+'%':'N/A'],['Expense Rate',income>0?((totalOut/income)*100).toFixed(1)+'%':'N/A'],['Investment Rate',income>0?((invest/income)*100).toFixed(1)+'%':'N/A'],['Total Records',Object.values(STATE.records).flat().length+' entries']].map(([l,v])=>`<div class="report-row"><span>${l}</span><span class="report-val">${v}</span></div>`).join('')}
      </div>
      ${catBreakdown('income').length?`<div class="report-card"><h4>💰 Income by Category</h4>${catBreakdown('income').map(([c,v])=>`<div class="report-row"><span>${c}</span><span class="report-val" style="color:var(--green)">${fmt(v)}</span></div>`).join('')}</div>`:''}
      ${catBreakdown('expense').length?`<div class="report-card"><h4>💸 Expenses by Category</h4>${catBreakdown('expense').map(([c,v])=>`<div class="report-row"><span>${c}</span><span class="report-val" style="color:var(--red)">${fmt(v)}</span></div>`).join('')}</div>`:''}
      ${catBreakdown('investment').length?`<div class="report-card"><h4>📈 Investments by Type</h4>${catBreakdown('investment').map(([c,v])=>`<div class="report-row"><span>${c}</span><span class="report-val" style="color:var(--accent)">${fmt(v)}</span></div>`).join('')}</div>`:''}
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;">
      <button class="btn-add" onclick="exportData()">⬇ Export JSON</button>
      <button class="btn-add" style="background:linear-gradient(135deg,var(--accent3),var(--accent))" onclick="exportCSV()">📄 Export CSV</button>
    </div>`;
}

function exportCSV() {
  const all = Object.entries(STATE.records).flatMap(([type,arr])=>arr.map(r=>`${type},${r.title},${r.amount},${r.category},${r.date},${r.notes||''},${r.returnPct||''},${r.target||''}`));
  const blob = new Blob([['Type,Title,Amount,Category,Date,Notes,ReturnPct,Target',...all].join('\n')],{type:'text/csv'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url;
  a.download=`wealthos_${new Date().toISOString().split('T')[0]}.csv`; a.click(); URL.revokeObjectURL(url);
  showToast('CSV exported!','success');
}

let toastTimer = null;
function showToast(msg, type='success') {
  const toast = document.getElementById('toast'); toast.textContent = msg;
  toast.className = `toast show ${type}`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{toast.className='toast';}, 3000);
}
function showError(msg) { document.getElementById('loginError').textContent = msg; }
function clearError() { document.getElementById('loginError').textContent = ''; }

let autoLockTimer = null;
function resetAutoLock() { if (!STATE.user) return; clearTimeout(autoLockTimer); autoLockTimer = setTimeout(()=>{showToast('Auto-locked after inactivity.','error');logout();}, 15*60*1000); }
['click','keydown','mousemove','touchstart'].forEach(ev=>document.addEventListener(ev,resetAutoLock,{passive:true}));
document.addEventListener('keydown', e=>{if((e.ctrlKey||e.metaKey)&&e.key==='l'&&STATE.user){e.preventDefault();logout();}});
document.getElementById('loginName').focus();

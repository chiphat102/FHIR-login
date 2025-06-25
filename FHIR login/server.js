const express = require('express');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args)); // ✅ 使用這個
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const sendResetEmail = require('./sendResetEmail');

const app = express();
app.use(express.json());
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: '你的 Gmail 地址',
    pass: '你的應用程式密碼' // 不是登入密碼，是 Gmail 的應用程式密碼
  }
});

// === Constants ===
const JWT_SECRET = 'your_fhir_secret_123';
const FHIR_BASE = 'https://hapi.fhir.org/baseR4';
const LOGIN_ID_SYSTEM = 'http://example.org/fhir/login-id';
const EMAIL_SYSTEM = 'http://example.org/fhir/email';
const PASSWORD_SYSTEM = 'http://example.org/fhir/password';

const IDENTIFIER_SYSTEMS = [LOGIN_ID_SYSTEM, EMAIL_SYSTEM];

app.use(express.static(path.join(__dirname)));

// Redirect root URL to login.html
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password)
    return res.status(400).json({ error: '缺少必要資料' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const personId = decoded.id;

    const resGet = await fetch(`${FHIR_BASE}/Person/${personId}`);
    if (!resGet.ok) throw new Error('FHIR Person 資料讀取失敗');

    const person = await resGet.json();

    // ✅ 移除舊密碼欄位，加入新密碼
    person.identifier = (person.identifier || []).filter(i => i.system !== PASSWORD_SYSTEM);
    person.identifier.push({
      system: PASSWORD_SYSTEM,
      value: await bcrypt.hash(password, 10)
    });

    const updateRes = await fetch(`${FHIR_BASE}/Person/${personId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/fhir+json' },
      body: JSON.stringify(person)
    });

    if (!updateRes.ok) {
      const errText = await updateRes.text();
      throw new Error(errText);
    }

    res.json({ message: '密碼已成功更新' });
  } catch (err) {
    res.status(500).json({ error: '密碼重設失敗', detail: err.message });
  }
});


//重設密碼Endpoint
app.post('/api/request-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '請輸入 Email' });

  try {
    const searchUrl = `${FHIR_BASE}/Person?identifier=http://example.org/fhir/email|${encodeURIComponent(email)}`;
    const fhirRes = await fetch(searchUrl);
    const data = await fhirRes.json();
    if (data.total === 0) return res.status(404).json({ error: '查無此帳號' });

    const personId = data.entry[0].resource.id;
    const token = jwt.sign({ id: personId, email }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `http://localhost:3000/forgot.html?token=${token}`;

    await sendResetEmail(email, resetLink);
    res.json({ message: '已寄出密碼重設連結' });
  } catch (err) {
    res.status(500).json({ error: '寄信失敗', detail: err.message });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password)
    return res.status(400).json({ error: '缺少必要資料' });

  try {
    // 驗證 token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const personId = decoded.id;

    // 取得該使用者的 FHIR Person 資料
    const resGet = await fetch(`${FHIR_BASE}/Person/${personId}`);
    if (!resGet.ok) throw new Error('FHIR Person 資料讀取失敗');
    const person = await resGet.json();

    // 加密新密碼
    const newHashed = await bcrypt.hash(password, 10);

    // 🔥 移除所有舊的密碼欄位
    person.identifier = person.identifier.filter(i => i.system !== PASSWORD_SYSTEM);

    // ✅ 加入新的 hashed 密碼
    person.identifier.push({
      system: PASSWORD_SYSTEM,
      value: newHashed
    });

    // 更新到 FHIR 伺服器
    const updateRes = await fetch(`${FHIR_BASE}/Person/${personId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/fhir+json' },
      body: JSON.stringify(person)
    });

    if (!updateRes.ok) throw new Error('FHIR 更新失敗');
    res.json({ message: '密碼已成功更新' });
  } catch (err) {
    res.status(500).json({ error: '密碼重設失敗', detail: err.message });
  }
});


// === Register Endpoint ===
app.post('/api/register', async (req, res) => {
  const { name, loginId,  email, password, phone, birthday } = req.body;

  if (!name || !loginId || !email || !password||!phone||!birthday)
    return res.status(400).json({ error: '所有欄位都必填' });

  try {
    // Check login ID
    const loginCheckUrl = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(LOGIN_ID_SYSTEM)}|${encodeURIComponent(loginId)}`;
    const loginRes = await fetch(loginCheckUrl);
    const loginData = await loginRes.json();
    if (loginData.total > 0) return res.status(409).json({ error: '此 login-id 已存在' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create Person resource
    const person = {
      resourceType: 'Person',
      name: [{ text: name }],
      birthday: [{value: birthday}],
      identifier: [
        { system: LOGIN_ID_SYSTEM, value: loginId },
        { system: EMAIL_SYSTEM, value: email },
        { system: PASSWORD_SYSTEM, value: hashedPassword }
      ],
      telecom: [
        { system: 'email', value: email, use: 'home' },
        {system: 'phone', value: phone, use: 'home'}
      ]
    };

    // Post to FHIR server
    const fhirRes = await fetch(`${FHIR_BASE}/Person`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/fhir+json' },
      body: JSON.stringify(person)
    });

    if (!fhirRes.ok) {
      const errText = await fhirRes.text();
      return res.status(500).json({ error: 'FHIR 建立失敗', detail: errText });
    }

    const result = await fhirRes.json();
    res.json({ message: '註冊成功', fhirId: result.id });
  } catch (err) {
    res.status(500).json({ error: '連接 FHIR 錯誤', detail: err.message });
  }
});

// === Login Endpoint ===
app.post('/api/login', async (req, res) => {
  const { loginId: input, password } = req.body;
  let person = null;

  try {
    for (const system of IDENTIFIER_SYSTEMS) {
      const searchUrl = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(system)}|${encodeURIComponent(input)}` || 
      `${FHIR_BASE}/Person?text=${encodeURIComponent(input)}`;
      const fhirRes = await fetch(searchUrl);
      const fhirData = await fhirRes.json();

      if (fhirData.total > 0) {
        person = fhirData.entry[0].resource;
        break;
      }
    }

    if (!person) return res.status(401).json({ error: '使用者不存在' });

    // Get loginId
    const loginIdEntry = person.identifier.find(i => i.system === LOGIN_ID_SYSTEM);
    if (!loginIdEntry) return res.status(401).json({ error: '缺少 login-id 欄位' });

    const loginId = loginIdEntry.value;

    // Get hashed password
    const hashEntry = person.identifier.find(i => i.system === PASSWORD_SYSTEM);
    if (!hashEntry) return res.status(401).json({ error: '密碼欄位缺失' });

    const isValid = await bcrypt.compare(password, hashEntry.value);
    if (!isValid) return res.status(401).json({ error: '密碼錯誤' });

    // Return JWT
    const token = jwt.sign({ id: person.id, loginId }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: '登入成功', token, person });

  } catch (err) {
    res.status(500).json({ error: '登入失敗', detail: err.message });
  }
});


app.post('/api/forgot', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '請輸入 Email' });

  try {
    const searchUrl = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    const fhirRes = await fetch(searchUrl);
    if (!fhirRes.ok) throw new Error('FHIR 查詢失敗');

    const data = await fhirRes.json();
    if (data.total === 0) return res.status(404).json({ error: '找不到該 Email 的使用者' });

    const person = data.entry[0].resource;
    const name = person.name?.[0]?.text || '(未提供)';
    const loginId = person.identifier.find(i => i.system === LOGIN_ID_SYSTEM)?.value || '(未提供)';

    res.json({ message: '查詢成功', name, loginId });
  } catch (err) {
    res.status(500).json({ error: '伺服器錯誤', detail: err.message });
  }
});


// Optional: serve static test file if needed
app.use('/fhir', express.static(__dirname + '/fhir-data'));

app.listen(3000, () => console.log('Server running at http://localhost:3000'));

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Prosta funkcja haszująca dla bezpieczeństwa
const simpleHash = (str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString();
};

// --- TWOJA BAZA DANYCH (Zaktualizowana) ---
let USERS = [
    { id: 1, username: 'admin1', password: simpleHash('123'), role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'active' },
    { id: 4, username: 'admin2', password: simpleHash('123'), role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik', status: 'active' }
];

let USER_PROGRESS = {};

// --- ENDPOINTY ---

// Rejestracja
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    if (USERS.find(u => u.username === username)) {
        return res.status(400).json({ success: false, message: 'Login zajęty.' });
    }
    const newUser = {
        id: Date.now(),
        username,
        password: simpleHash(password),
        role: 'user',
        teamId: teamId || null,
        name,
        status: 'pending' // Nowe konto zawsze oczekuje
    };
    USERS.push(newUser);
    res.json({ success: true, message: 'Konto utworzone. Czekaj na akceptację drużynowego.' });
});

// Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === simpleHash(password));
    
    if (!user) return res.status(401).json({ success: false, message: 'Błędne dane logowania.' });
    if (user.status !== 'active') return res.status(403).json({ success: false, message: 'Twoje konto jeszcze nie zostało zaakceptowane.' });
    
    res.json({ success: true, user });
});

// Pobieranie członków (tylko dla admina danej drużyny)
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Brak uprawnień' });

    const members = USERS.filter(u => u.teamId === admin.teamId && u.role === 'user');
    res.json(members);
});

// Akceptacja użytkownika
app.post('/api/change-status', (req, res) => {
    const { adminId, targetUserId, newStatus } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    const target = USERS.find(u => u.id === targetUserId);

    if (!admin || admin.role !== 'admin' || !target || target.teamId !== admin.teamId) {
        return res.status(403).json({ success: false });
    }

    target.status = newStatus;
    res.json({ success: true });
});

// USUWANIE UŻYTKOWNIKA
app.post('/api/delete-user', (req, res) => {
    const { adminId, targetUserId } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    const target = USERS.find(u => u.id === targetUserId);

    if (!admin || admin.role !== 'admin' || !target || target.teamId !== admin.teamId) {
        return res.status(403).json({ success: false, message: 'Brak uprawnień do usunięcia tego profilu.' });
    }

    USERS = USERS.filter(u => u.id !== targetUserId);
    delete USER_PROGRESS[targetUserId];
    res.json({ success: true });
});

// Postępy
app.get('/api/progress/:userId', (req, res) => {
    res.json(USER_PROGRESS[req.params.userId] || {});
});

app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body;
    if (!USER_PROGRESS[userId]) USER_PROGRESS[userId] = {};
    if (status) USER_PROGRESS[userId][taskId] = true;
    else delete USER_PROGRESS[userId][taskId];
    res.json({ success: true });
});

app.listen(3000, () => console.log('Serwer działa na http://localhost:3000'));

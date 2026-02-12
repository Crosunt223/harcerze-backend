const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();

// Konfiguracja CORS - musi być przed endpointami!
app.use(cors());
app.use(bodyParser.json());

// --- DANE ---
const TEAMS = [
    { id: 'team_las', name: 'Leśna Szkółka' },
    { id: 'team_woda', name: 'Wodne Wilki' },
    { id: 'team_ogien', name: 'Ogniste Ptaki' }
];

let USERS = [
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'approved' }
];

let USER_PROGRESS = {}; 

// --- ENDPOINTY ---

// Pobieranie drużyn - to wywołuje index.html
app.get('/api/teams', (req, res) => {
    console.log("LOG: Ktoś pyta o listę drużyn...");
    res.json(TEAMS);
});

app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Login zajęty!' });
    }
    const newUser = { id: Date.now(), username, password, name, teamId, role: 'user', status: 'pending' };
    USERS.push(newUser);
    res.json({ success: true, message: 'Wysłano prośbę o dołączenie!' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ success: false, message: 'Błędne dane' });
    if (user.status === 'pending') return res.status(403).json({ success: false, message: 'Czekaj na akceptację' });
    res.json({ success: true, user });
});

app.get('/api/pending-requests', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin') return res.status(403).send('Brak uprawnień');
    res.json(USERS.filter(u => u.teamId === admin.teamId && u.status === 'pending'));
});

app.post('/api/approve-user', (req, res) => {
    const { adminId, userId } = req.body;
    const user = USERS.find(u => u.id === userId);
    if (user) user.status = 'approved';
    res.json({ success: true });
});

app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    res.json(USERS.filter(u => u.teamId === admin.teamId && u.role === 'user' && u.status === 'approved'));
});

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

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`=================================`);
    console.log(`SERWER DZIAŁA NA: http://localhost:${PORT}`);
    console.log(`=================================`);
});

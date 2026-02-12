const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- BAZA DANYCH (Symulacja) ---
const TEAMS = [
    { id: 'team_las', name: 'Leśna Szkółka' },
    { id: 'team_woda', name: 'Wodne Wilki' }
];

let USERS = [
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'approved' }
];

let USER_PROGRESS = {}; 

// --- ENDPOINTY API ---

// Pobieranie list drużyn
app.get('/api/teams', (req, res) => res.json(TEAMS));

// Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);
    if (user) {
        res.json({ success: true, user });
    } else {
        res.status(401).json({ success: false, message: 'Błędne dane logowania' });
    }
});

// Rejestracja
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Login zajęty!' });
    }
    const newUser = { id: Date.now(), username, password, name, teamId, role: 'user', status: 'approved' };
    USERS.push(newUser);
    res.json({ success: true, user: newUser });
});

// Pobieranie członków drużyny dla admina
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin') return res.status(403).json([]);
    const members = USERS.filter(u => u.teamId === admin.teamId && u.role === 'user');
    res.json(members);
});

// Postępy
app.get('/api/progress/:userId', (req, res) => res.json(USER_PROGRESS[req.params.userId] || {}));

app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body;
    if (!USER_PROGRESS[userId]) USER_PROGRESS[userId] = {};
    if (status) USER_PROGRESS[userId][taskId] = true;
    else delete USER_PROGRESS[userId][taskId];
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer na porcie ${PORT}`));

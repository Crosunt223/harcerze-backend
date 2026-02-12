const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- BAZA DANYCH ---

const TEAMS = [
    { id: 'team_las', name: 'Leśne Skrzaty' },
    { id: 'team_woda', name: 'Wodne Wilki' },
    { id: 'team_ogien', name: 'Ogniste Ptaki' }
];

let USERS = [
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'approved' },
    { id: 2, username: 'user1', password: '123', role: 'user', teamId: 'team_las', name: 'Harcerz Janek', status: 'approved' }
];

let USER_PROGRESS = {}; 

// --- ENDPOINTY API ---

// 1. POBIERANIE DRUŻYN (Tego brakowało!)
app.get('/api/teams', (req, res) => {
    res.json(TEAMS);
});

// 2. REJESTRACJA (Tego też brakowało!)
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Login zajęty!' });
    }
    // Nowy user ma status 'pending' (czeka na akceptację) lub 'approved' (jeśli wolisz bez akceptacji)
    const newUser = { 
        id: Date.now(), 
        username, 
        password, 
        name, 
        teamId, 
        role: 'user', 
        status: 'pending' 
    };
    USERS.push(newUser);
    res.json({ success: true, message: 'Konto utworzone! Czekaj na akceptację drużynowego.' });
});

// 3. LOGOWANIE
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);

    if (!user) return res.status(401).json({ success: false, message: 'Błędne dane' });
    if (user.status === 'pending') return res.status(403).json({ success: false, message: 'Konto czeka na akceptację' });
    
    res.json({ success: true, user });
});

// 4. PANEL ADMINA - OCZEKUJĄCE PROŚBY
app.get('/api/pending-requests', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin') return res.status(403).send('Brak uprawnień');
    
    // Zwraca osoby z tej samej drużyny co admin, które mają status pending
    res.json(USERS.filter(u => u.teamId === admin.teamId && u.status === 'pending'));
});

// 5. AKCEPTACJA UŻYTKOWNIKA
app.post('/api/approve-user', (req, res) => {
    const { adminId, userId } = req.body;
    const user = USERS.find(u => u.id === userId);
    if (user) user.status = 'approved';
    res.json({ success: true });
});

// 6. CZŁONKOWIE DRUŻYNY (Dla Admina)
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin) return res.json([]);

    const members = USERS.filter(u => u.teamId === admin.teamId && u.role === 'user' && u.status === 'approved');
    res.json(members);
});

// 7. PROGRESS
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});

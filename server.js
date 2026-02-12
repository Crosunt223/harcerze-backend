const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors()); // Pozwala na komunikację między index.html a serwerem
app.use(bodyParser.json());

// --- KONFIGURACJA DRUŻYN ---
const TEAMS = [
    { id: 'team_las', name: 'Leśna Szkółka' },
    { id: 'team_woda', name: 'Wodne Wilki' },
    { id: 'team_ogien', name: 'Ogniste Ptaki' }
];

// --- BAZA UŻYTKOWNIKÓW (W RAM) ---
let USERS = [
    // Predefiniowani admini
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'approved' },
    { id: 4, username: 'admin2', password: '123', role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik', status: 'approved' }
];

let USER_PROGRESS = {}; 

// --- ENDPOINTY ---

// Pobieranie listy drużyn (to musi działać, by select w HTML się wypełnił)
app.get('/api/teams', (req, res) => {
    console.log("Pobieranie listy drużyn...");
    res.json(TEAMS);
});

// Rejestracja nowego użytkownika
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Login zajęty!' });
    }

    const newUser = {
        id: Date.now(),
        username,
        password,
        name,
        teamId,
        role: 'user',
        status: 'pending' // Wymaga akceptacji admina
    };

    USERS.push(newUser);
    console.log(`Nowy użytkownik zarejestrowany: ${name} (oczekuje na akceptację)`);
    res.json({ success: true, message: 'Wysłano prośbę o dołączenie. Poczekaj na akceptację admina.' });
});

// Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).json({ success: false, message: 'Błędne dane logowania!' });
    }
    
    if (user.status === 'pending') {
        return res.status(403).json({ success: false, message: 'Twoje konto czeka na akceptację przez admina.' });
    }

    res.json({ success: true, user });
});

// Pobieranie próśb o dołączenie dla danego admina
app.get('/api/pending-requests', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    
    if (!admin || admin.role !== 'admin') return res.status(403).send('Brak uprawnień');

    const pending = USERS.filter(u => u.teamId === admin.teamId && u.status === 'pending');
    res.json(pending);
});

// Akceptacja użytkownika
app.post('/api/approve-user', (req, res) => {
    const { adminId, userId } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    
    if (!admin || admin.role !== 'admin') return res.status(403).send('Brak uprawnień');

    const user = USERS.find(u => u.id === userId);
    if (user) {
        user.status = 'approved';
        res.json({ success: true });
    }
});

// Członkowie drużyny
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    if (!admin) return res.status(403).send('Błąd');

    const members = USERS.filter(u => u.teamId === admin.teamId && u.role === 'user' && u.status === 'approved');
    res.json(members);
});

// Postęp
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
app.listen(PORT, () => console.log(`SERWER DZIAŁA: http://localhost:${PORT}`));

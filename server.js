const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors()); // Pozwala na połączenie z Twoim index.html
app.use(bodyParser.json());

// --- BAZA DANYCH (W Pamięci RAM serwera) ---
// Dane znikną po restarcie serwera (np. po nowym deployu na Render)

const TEAMS = [
    { id: 'team_las', name: 'Leśna Szkółka' },
    { id: 'team_woda', name: 'Wodne Wilki' },
    { id: 'team_ogien', name: 'Ogniste Ptaki' }
];

let USERS = [
    // Domyślni Admini
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'approved' },
    { id: 2, username: 'admin2', password: '123', role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik', status: 'approved' }
];

// Postępy zadań: { "userId": { "taskId": true } }
let USER_PROGRESS = {}; 

// --- ENDPOINTY API ---

// 1. Lista drużyn
app.get('/api/teams', (req, res) => {
    res.json(TEAMS);
});

// 2. Rejestracja
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Ten login jest już zajęty!' });
    }

    const newUser = {
        id: Date.now(),
        username,
        password, // W prawdziwej aplikacji tutaj powinno być hashowanie
        name,
        teamId,
        role: 'user',
        status: 'pending' // Czeka na akceptację
    };

    USERS.push(newUser);
    console.log(`Nowy użytkownik: ${name} (${teamId})`);
    res.json({ success: true, message: 'Konto utworzone! Czekaj na akceptację Drużynowego.' });
});

// 3. Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);

    if (!user) return res.status(401).json({ success: false, message: 'Błędny login lub hasło' });
    
    if (user.status === 'pending') {
        return res.status(403).json({ success: false, message: 'Twoje konto czeka na akceptację przez admina.' });
    }

    res.json({ success: true, user });
});

// 4. Pobierz członków drużyny (Dla Admina)
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    
    if (!admin || admin.role !== 'admin') return res.status(403).json([]);

    // Zwraca tylko zaakceptowanych członków tej samej drużyny
    const members = USERS.filter(u => u.teamId === admin.teamId && u.role === 'user' && u.status === 'approved');
    res.json(members);
});

// 5. Pobierz oczekujące prośby (Dla Admina)
app.get('/api/pending-requests', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);
    
    if (!admin || admin.role !== 'admin') return res.status(403).json([]);

    const pending = USERS.filter(u => u.teamId === admin.teamId && u.status === 'pending');
    res.json(pending);
});

// 6. Akceptuj użytkownika
app.post('/api/approve-user', (req, res) => {
    const { adminId, userId } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    
    if (!admin || admin.role !== 'admin') return res.status(403).json({ success: false });

    const userToApprove = USERS.find(u => u.id === userId);
    if (userToApprove) {
        userToApprove.status = 'approved';
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false });
    }
});

// 7. Pobierz postęp
app.get('/api/progress/:userId', (req, res) => {
    const uid = req.params.userId;
    res.json(USER_PROGRESS[uid] || {});
});

// 8. Zapisz postęp
app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body;
    
    if (!USER_PROGRESS[userId]) USER_PROGRESS[userId] = {};
    
    if (status) USER_PROGRESS[userId][taskId] = true;
    else delete USER_PROGRESS[userId][taskId];

    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));

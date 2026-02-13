const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- BAZA DANYCH W PAMIĘCI (RAM) ---
// Te dane znikną po restarcie serwera, ale nie tworzą plików .json

let USERS = [
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'active' },
    { id: 4, username: 'admin2', password: '123', role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik', status: 'active' }
];

let USER_PROGRESS = {}; // Format: { userId: { taskId: true } }

// Prosty "hash" (zamiana tekstu na kod, żeby nie trzymać haseł czystym tekstem)
const hashPass = (p) => p.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0).toString();

// Podmieniamy hasła początkowe na hashe
USERS.forEach(u => u.password = hashPass(u.password));

// --- ENDPOINTY API ---

// 1. Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === hashPass(password));
    
    if (user) {
        res.json({ success: true, user });
    } else {
        res.status(401).json({ success: false, message: 'Błędny login lub hasło' });
    }
});

// 2. Rejestracja
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    
    if (USERS.find(u => u.username === username)) {
        return res.json({ success: false, message: 'Ten login jest już zajęty' });
    }

    const newUser = {
        id: Date.now(),
        username,
        password: hashPass(password),
        name,
        teamId,
        role: 'user',
        status: 'pending' // Nowy użytkownik zawsze czeka na akceptację
    };

    USERS.push(newUser);
    res.json({ success: true });
});

// 3. Pobieranie członków dla Admina (tylko z jego drużyny)
app.get('/api/team-members', (req, res) => {
    const { adminId } = req.query;
    const admin = USERS.find(u => u.id == adminId);

    if (!admin || admin.role !== 'admin') return res.status(403).send();

    // Admin widzi wszystkich ze swojej drużyny (oprócz siebie)
    const members = USERS.filter(u => u.teamId === admin.teamId && u.id != adminId);
    res.json(members);
});

// 4. Akceptacja/Odrzucenie użytkownika
app.post('/api/user-status', (req, res) => {
    const { userId, status } = req.body; // status: 'active' lub 'rejected'
    const userIdx = USERS.findIndex(u => u.id == userId);
    
    if (userIdx !== -1) {
        USERS[userIdx].status = status;
        res.json({ success: true });
    } else {
        res.status(404).json({ message: "Nie znaleziono użytkownika" });
    }
});

// 5. Usuwanie konta (użytkownik sam siebie lub admin kogoś)
app.delete('/api/user/:id', (req, res) => {
    const id = req.params.id;
    USERS = USERS.filter(u => u.id != id);
    delete USER_PROGRESS[id];
    res.json({ success: true });
});

// 6. Zarządzanie postępem
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

app.listen(3000, () => console.log('Serwer działa na porcie 3000 (Zapis w RAM)'));

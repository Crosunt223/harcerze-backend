const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- POMOCNICZE ---
const simpleHash = (str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString();
};

// --- DANE ---
let USERS = [
    { id: 1, username: 'admin1', password: simpleHash('123'), role: 'admin', teamId: 'team_las', name: 'Druh Boruch', status: 'active' },
    { id: 4, username: 'admin2', password: simpleHash('123'), role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik', status: 'active' }
];
let USER_PROGRESS = {};

// --- ENDPOINTY ---

// Rejestracja
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;
    if (USERS.find(u => u.username === username)) return res.status(400).json({ success: false, message: 'Login zajęty' });
    
    const newUser = { id: Date.now(), username, password: simpleHash(password), role: 'user', teamId, name, status: 'pending' };
    USERS.push(newUser);
    res.json({ success: true, message: 'Oczekiwanie na akceptację.' });
});

// Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === simpleHash(password));
    if (!user) return res.status(401).json({ success: false, message: 'Błędne dane' });
    if (user.status !== 'active') return res.status(403).json({ success: false, message: 'Konto nieaktywne' });
    res.json({ success: true, user });
});

// Zmiana statusu (Akceptacja)
app.post('/api/change-status', (req, res) => {
    const { adminId, targetUserId, newStatus } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    const user = USERS.find(u => u.id === targetUserId);

    if (admin?.role !== 'admin' || user?.teamId !== admin.teamId) return res.status(403).send();

    user.status = newStatus;
    res.json({ success: true });
});

// CAŁKOWITE USUNIĘCIE UŻYTKOWNIKA (Nowość)
app.post('/api/delete-user', (req, res) => {
    const { adminId, targetUserId } = req.body;
    const admin = USERS.find(u => u.id === adminId);
    
    // Sprawdzenie uprawnień
    const targetUser = USERS.find(u => u.id === targetUserId);
    if (!admin || admin.role !== 'admin' || !targetUser || targetUser.teamId !== admin.teamId) {
        return res.status(403).json({ success: false, message: 'Brak uprawnień' });
    }

    // Usuwanie z listy użytkowników
    USERS = USERS.filter(u => u.id !== targetUserId);
    // Czyszczenie postępów użytkownika
    delete USER_PROGRESS[targetUserId];

    console.log(`Użytkownik ${targetUserId} został usunięty przez admina ${adminId}`);
    res.json({ success: true });
});

// Postępy
app.get('/api/progress/:userId', (req, res) => res.json(USER_PROGRESS[req.params.userId] || {}));
app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body;
    if (!USER_PROGRESS[userId]) USER_PROGRESS[userId] = {};
    status ? USER_PROGRESS[userId][taskId] = true : delete USER_PROGRESS[userId][taskId];
    res.json({ success: true });
});

app.get('/api/team-members', (req, res) => {
    const admin = USERS.find(u => u.id === parseInt(req.query.adminId));
    res.json(USERS.filter(u => u.teamId === admin?.teamId && u.role === 'user'));
});

app.listen(3000, () => console.log('Server running on port 3000'));

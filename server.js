const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- BAZA DANYCH (Symulacja w pamięci RAM) ---
// W prawdziwej aplikacji użyłbyś MongoDB lub PostgreSQL.

const TEAMS = [
    { id: 'team_las', name: 'Leśne Skrzaty' },
    { id: 'team_woda', name: 'Wodne Wilki' }
];

const USERS = [
    // Drużyna Leśne Skrzaty
    { id: 1, username: 'admin1', password: '123', role: 'admin', teamId: 'team_las', name: 'Druh Boruch' },
    { id: 2, username: 'user1', password: '123', role: 'user', teamId: 'team_las', name: 'Harcerz Janek' },
    { id: 3, username: 'user2', password: '123', role: 'user', teamId: 'team_las', name: 'Harcerz Zosia' },
    
    // Drużyna Wodne Wilki
    { id: 4, username: 'admin2', password: '123', role: 'admin', teamId: 'team_woda', name: 'Druh Wodnik' },
    { id: 5, username: 'user3', password: '123', role: 'user', teamId: 'team_woda', name: 'Harcerz Tomek' }
];

// Tutaj przechowujemy postępy: { userId: { "taskId": true, ... } }
let USER_PROGRESS = {}; 

// --- ENDPOINTY API ---

// 1. Logowanie
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS.find(u => u.username === username && u.password === password);

    if (user) {
        res.json({ 
            success: true, 
            user: { id: user.id, username: user.username, role: user.role, teamId: user.teamId, name: user.name } 
        });
    } else {
        res.status(401).json({ success: false, message: 'Błędne dane' });
    }
});

// 2. Pobierz członków drużyny (Tylko dla admina tej drużyny)
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);

    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ error: 'Brak uprawnień' });
    }

    // Zwróć użytkowników z tej samej drużyny (bez haseł)
    const members = USERS
        .filter(u => u.teamId === admin.teamId && u.role === 'user')
        .map(({ password, ...user }) => user);

    res.json(members);
});

// 3. Pobierz postęp konkretnego użytkownika
app.get('/api/progress/:userId', (req, res) => {
    const userId = req.params.userId;
    const progress = USER_PROGRESS[userId] || {};
    res.json(progress);
});

// 4. Zapisz postęp (Zaliczenie sprawności)
app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body; // status = true (zaliczone) lub false (cofnięte)
    
    if (!USER_PROGRESS[userId]) {
        USER_PROGRESS[userId] = {};
    }

    if (status) {
        USER_PROGRESS[userId][taskId] = true;
    } else {
        delete USER_PROGRESS[userId][taskId];
    }

    res.json({ success: true, progress: USER_PROGRESS[userId] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);

// 5. Rejestracja nowego użytkownika
app.post('/api/register', (req, res) => {
    const { username, password, name } = req.body;

    // Sprawdź czy użytkownik już istnieje
    const existingUser = USERS.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ success: false, message: 'Ten login jest zajęty' });
    }

    // Tworzymy nowego użytkownika
    // Domyślnie dajemy mu rolę 'user' i przypisujemy do pierwszej drużyny
    const newUser = {
        id: USERS.length + 1, // Proste generowanie ID
        username: username,
        password: password,
        role: 'user',
        teamId: 'team_las', // Możesz to zmienić na wybór z listy w UI
        name: name || 'Nowy Harcerz'
    };

    USERS.push(newUser);
    
    // Logujemy go od razu po rejestracji (opcjonalnie)
    res.json({ 
        success: true, 
        user: { id: newUser.id, username: newUser.username, role: newUser.role, teamId: newUser.teamId, name: newUser.name } 
    });
});

});

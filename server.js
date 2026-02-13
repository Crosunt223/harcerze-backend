const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- FUNKCJE POMOCNICZE ---

// Prosta funkcja haszująca (dla celów edukacyjnych, w produkcji użyj bcrypt)
const simpleHash = (str) => {
    let hash = 0;
    if (str.length === 0) return hash.toString();
    for (let i = 0; i < str.length; i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0; 
    }
    return hash.toString();
};

// --- BAZA DANYCH (Symulacja w pamięci RAM) ---

const TEAMS = [
    { id: 'team_las', name: 'Leśne Skrzaty' },
    { id: 'team_woda', name: 'Wodne Wilki' }
];

// Startowi użytkownicy (z zahaszowanymi hasłami)
const USERS = [
    // Drużyna Leśne Skrzaty (Admin)
    { 
        id: 1, 
        username: 'admin1', 
        password: simpleHash('123'), // Hasło: 123
        role: 'admin', 
        teamId: 'team_las', 
        name: 'Druh Boruch',
        status: 'active' 
    },
    // Drużyna Wodne Wilki (Admin)
    { 
        id: 4, 
        username: 'admin2', 
        password: simpleHash('123'), // Hasło: 123
        role: 'admin', 
        teamId: 'team_woda', 
        name: 'Druh Wodnik',
        status: 'active' 
    }
];

// Postępy: { userId: { "taskId": true, ... } }
let USER_PROGRESS = {}; 

// --- ENDPOINTY API ---

// 1. Rejestracja (NOWOŚĆ)
app.post('/api/register', (req, res) => {
    const { username, password, name, teamId } = req.body;

    // Walidacja
    if (!username || !password || !name || !teamId) {
        return res.status(400).json({ success: false, message: 'Wypełnij wszystkie pola.' });
    }

    // Sprawdź czy login zajęty
    if (USERS.find(u => u.username === username)) {
        return res.status(400).json({ success: false, message: 'Login zajęty.' });
    }

    // Utwórz użytkownika
    const newUser = {
        id: Date.now(), // Unikalne ID
        username,
        password: simpleHash(password), // Zapisujemy hasz!
        role: 'user',
        teamId,
        name,
        status: 'pending' // Domyślnie oczekujący
    };

    USERS.push(newUser);
    console.log(`Zarejestrowano: ${username} (${teamId})`);

    res.json({ success: true, message: 'Konto utworzone. Oczekuje na akceptację drużynowego.' });
});

// 2. Logowanie (ZAKTUALIZOWANE)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = simpleHash(password);

    const user = USERS.find(u => u.username === username && u.password === hashedPassword);

    if (user) {
        if (user.status !== 'active') {
            return res.status(403).json({ success: false, message: 'Konto oczekuje na akceptację.' });
        }

        res.json({ 
            success: true, 
            user: { id: user.id, username: user.username, role: user.role, teamId: user.teamId, name: user.name } 
        });
    } else {
        res.status(401).json({ success: false, message: 'Błędne dane logowania.' });
    }
});

// 3. Pobierz członków drużyny (ZAKTUALIZOWANE o status)
app.get('/api/team-members', (req, res) => {
    const adminId = parseInt(req.query.adminId);
    const admin = USERS.find(u => u.id === adminId);

    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ error: 'Brak uprawnień' });
    }

    // Zwróć wszystkich (aktywnych i oczekujących) z tej samej drużyny
    const members = USERS
        .filter(u => u.teamId === admin.teamId && u.role === 'user')
        .map(({ password, ...user }) => user); // Usuń hasła z wyniku

    res.json(members);
});

// 4. Zmiana statusu członka (NOWOŚĆ - Akceptacja/Odrzucenie)
app.post('/api/change-status', (req, res) => {
    const { adminId, targetUserId, newStatus } = req.body; // newStatus: 'active' lub 'rejected'
    
    const admin = USERS.find(u => u.id === adminId);
    if (!admin || admin.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Brak uprawnień admina.' });
    }

    const targetUser = USERS.find(u => u.id === targetUserId);
    if (!targetUser) {
        return res.status(404).json({ success: false, message: 'Nie znaleziono użytkownika.' });
    }

    // Sprawdzenie czy admin zarządza tą samą drużyną co user
    if (targetUser.teamId !== admin.teamId) {
        return res.status(403).json({ success: false, message: 'To nie Twój harcerz.' });
    }

    if (newStatus === 'rejected') {
        // Usuwamy użytkownika całkowicie (lub można zmienić status na 'banned')
        const index = USERS.indexOf(targetUser);
        if (index > -1) {
            USERS.splice(index, 1);
        }
    } else {
        targetUser.status = newStatus;
    }

    res.json({ success: true });
});

// 5. Pobierz postęp
app.get('/api/progress/:userId', (req, res) => {
    const userId = req.params.userId;
    const progress = USER_PROGRESS[userId] || {};
    res.json(progress);
});

// 6. Zapisz postęp
app.post('/api/progress', (req, res) => {
    const { userId, taskId, status } = req.body; 
    
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
});

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const JWT_SECRET = process.env.JWT_SECRET || 'harcerze_secret_2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/harcerze';

// ─── SCHEMAS ─────────────────────────────────────────────────────────────────

const teamSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' }
});

const userSchema = new mongoose.Schema({
    login:     { type: String, required: true, unique: true },
    password:  { type: String, required: true },
    nickname:  { type: String, required: true },
    team:      { type: String, default: null },
    role:      { type: String, enum: ['superadmin', 'admin', 'user'], default: 'user' },
    status:    { type: String, enum: ['pending', 'active', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const Team = mongoose.model('Team', teamSchema);
const User = mongoose.model('User', userSchema);

// ─── INIT ─────────────────────────────────────────────────────────────────────

async function initDB() {
    const defaultTeams = [
        { name: '1 Drużyna Harcerska "Leśne Wilki"', description: 'Drużyna nr 1' },
        { name: '2 Drużyna Harcerska "Orły"',         description: 'Drużyna nr 2' },
        { name: '3 Drużyna Harcerska "Sokoły"',       description: 'Drużyna nr 3' },
        { name: '4 Drużyna Harcerska "Rysie"',        description: 'Drużyna nr 4' },
        { name: '5 Drużyna Harcerska "Niedźwiedzie"', description: 'Drużyna nr 5' },
    ];
    for (const t of defaultTeams) {
        await Team.findOneAndUpdate({ name: t.name }, t, { upsert: true, new: true });
    }

    const existing = await User.findOne({ login: 'admin' });
    if (!existing) {
        const hashed = await bcrypt.hash('admin', 10);
        await User.create({
            login: 'admin', password: hashed,
            nickname: 'Administrator',
            role: 'superadmin', status: 'active', team: null
        });
        console.log('Konto admin/admin utworzone');
    }
    console.log('Baza danych zainicjalizowana');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Brak tokenu' });
    try {
        req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Nieprawidłowy token' });
    }
}

// ─── ENDPOINTY ────────────────────────────────────────────────────────────────

app.get('/api/ping', (req, res) => res.json({ status: 'ok', time: new Date() }));

// Lista drużyn — publiczna
app.get('/api/teams', async (req, res) => {
    try {
        const teams = await Team.find().sort({ name: 1 });
        res.json(teams);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Rejestracja
app.post('/api/register', async (req, res) => {
    try {
        const { login, password, nickname, team } = req.body;
        if (!login || !password || !nickname || !team)
            return res.status(400).json({ error: 'Wypełnij wszystkie pola' });

        if (await User.findOne({ login }))
            return res.status(400).json({ error: 'Login już zajęty' });

        if (!await Team.findOne({ name: team }))
            return res.status(400).json({ error: 'Drużyna nie istnieje' });

        const hashed = await bcrypt.hash(password, 10);
        const user = await User.create({
            login, password: hashed, nickname, team,
            role: 'user', status: 'pending'
        });
        res.json({ message: 'Konto utworzone, czeka na akceptację admina drużyny', userId: user._id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Logowanie
app.post('/api/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        if (!login || !password)
            return res.status(400).json({ error: 'Podaj login i hasło' });

        const user = await User.findOne({ login });
        if (!user) return res.status(401).json({ error: 'Nieprawidłowy login lub hasło' });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Nieprawidłowy login lub hasło' });

        if (user.status === 'pending')
            return res.status(403).json({ error: 'Konto czeka na akceptację admina' });
        if (user.status === 'rejected')
            return res.status(403).json({ error: 'Konto zostało odrzucone' });

        const token = jwt.sign(
            { id: user._id, login: user.login, role: user.role, team: user.team, nickname: user.nickname },
            JWT_SECRET, { expiresIn: '7d' }
        );
        res.json({ token, role: user.role, team: user.team, nickname: user.nickname, login: user.login });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Profil zalogowanego użytkownika
app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Członkowie drużyny
app.get('/api/team-members', authMiddleware, async (req, res) => {
    try {
        const { role, team } = req.user;
        if (role === 'superadmin') {
            const users = await User.find().select('-password').sort({ team: 1, status: 1 });
            return res.json(users);
        }
        if (role === 'admin') {
            const users = await User.find({ team }).select('-password').sort({ status: 1 });
            return res.json(users);
        }
        return res.status(403).json({ error: 'Brak uprawnień' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Zmień status użytkownika
app.patch('/api/users/:id/status', authMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        if (!['active', 'rejected', 'pending'].includes(status))
            return res.status(400).json({ error: 'Nieprawidłowy status' });

        const target = await User.findById(req.params.id);
        if (!target) return res.status(404).json({ error: 'Użytkownik nie znaleziony' });

        const { role, team } = req.user;
        if (role === 'admin' && target.team !== team)
            return res.status(403).json({ error: 'Możesz zarządzać tylko swoją drużyną' });
        if (role === 'user')
            return res.status(403).json({ error: 'Brak uprawnień' });

        target.status = status;
        await target.save();
        res.json({ message: 'Status zaktualizowany' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Zmień rolę — tylko superadmin
app.patch('/api/users/:id/role', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin')
            return res.status(403).json({ error: 'Tylko superadmin może zmieniać role' });

        const { role } = req.body;
        if (!['admin', 'user'].includes(role))
            return res.status(400).json({ error: 'Nieprawidłowa rola' });

        const target = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password');
        if (!target) return res.status(404).json({ error: 'Użytkownik nie znaleziony' });
        res.json({ message: 'Rola zaktualizowana', user: target });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Usuń użytkownika — tylko superadmin
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin')
            return res.status(403).json({ error: 'Tylko superadmin może usuwać konta' });

        const target = await User.findById(req.params.id);
        if (!target) return res.status(404).json({ error: 'Użytkownik nie znaleziony' });
        if (target.login === 'admin')
            return res.status(400).json({ error: 'Nie można usunąć głównego admina' });

        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Konto usunięte' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Dodaj drużynę — tylko superadmin
app.post('/api/teams', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin')
            return res.status(403).json({ error: 'Brak uprawnień' });
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ error: 'Podaj nazwę drużyny' });
        const team = await Team.create({ name, description: description || '' });
        res.json(team);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Usuń drużynę — tylko superadmin
app.delete('/api/teams/:id', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin')
            return res.status(403).json({ error: 'Brak uprawnień' });
        await Team.findByIdAndDelete(req.params.id);
        res.json({ message: 'Drużyna usunięta' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Dane postępu (istniejąca funkcjonalność)
const progressSchema = new mongoose.Schema({ userId: String, progress: Object });
const Progress = mongoose.model('Progress', progressSchema);

app.get('/api/progress/:userId', authMiddleware, async (req, res) => {
    try {
        const p = await Progress.findOne({ userId: req.params.userId });
        res.json(p ? p.progress : {});
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/progress/:userId', authMiddleware, async (req, res) => {
    try {
        await Progress.findOneAndUpdate(
            { userId: req.params.userId },
            { progress: req.body },
            { upsert: true }
        );
        res.json({ message: 'Zapisano' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── START ────────────────────────────────────────────────────────────────────

mongoose.connect(MONGODB_URI)
    .then(async () => {
        console.log('Polaczono z MongoDB');
        await initDB();
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => console.log('Serwer dziala na porcie ' + PORT));
    })
    .catch(err => {
        console.error('Blad polaczenia z MongoDB:', err.message);
        process.exit(1);
    });

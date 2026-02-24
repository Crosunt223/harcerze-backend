const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/harcerze';
const JWT_SECRET  = process.env.JWT_SECRET  || 'tajny_klucz_zmien_mnie';
const PORT        = process.env.PORT        || 3000;

// ================================================================
// MONGODB
// ================================================================

mongoose.connect(MONGODB_URI)
    .then(() => { console.log('MongoDB OK'); seedData(); })
    .catch(err => console.error('MongoDB BLAD:', err));

// ================================================================
// MODELE
// ================================================================

const teamSchema = new mongoose.Schema({
    teamId: { type: String, required: true, unique: true },
    name:   { type: String, required: true }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
    username:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    name:         { type: String, required: true },
    role:         { type: String, enum: ['superadmin','admin','user'], default: 'user' },
    teamId:       { type: String, default: null },
    status:       { type: String, enum: ['active','pending','rejected'], default: 'pending' }
}, { timestamps: true });

const progressSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, ref: 'User' },
    tasks:  { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

const Team     = mongoose.model('Team',     teamSchema);
const User     = mongoose.model('User',     userSchema);
const Progress = mongoose.model('Progress', progressSchema);

// ================================================================
// SEED — domyslne druzyny + konto admin/admin
// ================================================================

async function seedData() {
    // Domyslne druzyny
    // Aby dodac nowa druzyne — dodaj wiersz tutaj i wrzuc na GitHuba
    const druzyny = [
        { teamId: 'druzyna_1', name: '1 Druzyna Harcerska' },
        { teamId: 'druzyna_2', name: '2 Druzyna Harcerska' },
        { teamId: 'druzyna_3', name: '3 Druzyna Harcerska' },
        { teamId: 'druzyna_4', name: '4 Druzyna Harcerska' },
        { teamId: 'druzyna_5', name: '5 Druzyna Harcerska' },
    ];
    for (const d of druzyny) {
        await Team.findOneAndUpdate({ teamId: d.teamId }, d, { upsert: true, new: true });
    }
    console.log('Druzyny OK');

    // Super-admin — login: admin, haslo: admin
    const exists = await User.findOne({ username: 'admin' });
    if (!exists) {
        await User.create({
            username:     'admin',
            passwordHash: await bcrypt.hash('admin', 10),
            name:         'Super Admin',
            role:         'superadmin',
            teamId:       null,
            status:       'active'
        });
        console.log('Super-admin utworzony  login:admin  haslo:admin');
    }
}

// ================================================================
// MIDDLEWARE
// ================================================================

function requireAuth(req, res, next) {
    const h = req.headers['authorization'];
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokenu' });
    try {
        req.user = jwt.verify(h.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token nieprawidlowy' });
    }
}

function requireAdmin(req, res, next) {
    if (!['admin','superadmin'].includes(req.user.role))
        return res.status(403).json({ error: 'Brak uprawnien' });
    next();
}

function requireSuperAdmin(req, res, next) {
    if (req.user.role !== 'superadmin')
        return res.status(403).json({ error: 'Tylko super-admin' });
    next();
}

// ================================================================
// AUTH
// ================================================================

// Rejestracja
// Pierwszy uzytkownik w druzynie automatycznie zostaje adminem
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name, teamId } = req.body;

        if (!username || !password || !name || !teamId)
            return res.status(400).json({ success: false, message: 'Wszystkie pola sa wymagane' });
        if (username.trim().length < 3)
            return res.status(400).json({ success: false, message: 'Login min. 3 znaki' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Haslo min. 6 znakow' });
        if (await User.findOne({ username: username.toLowerCase().trim() }))
            return res.status(400).json({ success: false, message: 'Ten login jest zajety' });
        if (!(await Team.findOne({ teamId })))
            return res.status(400).json({ success: false, message: 'Druzyna nie istnieje' });

        const juzMaAdmina = await User.findOne({ teamId, role: 'admin', status: 'active' });
        const role   = juzMaAdmina ? 'user'    : 'admin';
        const status = juzMaAdmina ? 'pending' : 'active';

        await User.create({
            username: username.toLowerCase().trim(),
            passwordHash: await bcrypt.hash(password, 10),
            name: name.trim(), role, teamId, status
        });

        const msg = role === 'admin'
            ? 'Konto admina druzyny utworzone! Mozesz sie zalogowac.'
            : 'Konto utworzone! Czeka na akceptacje druzynowego.';

        res.json({ success: true, message: msg, role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Blad serwera: ' + err.message });
    }
});

// Logowanie — zwraca JWT wazny 7 dni
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ success: false, message: 'Podaj login i haslo' });

        const user = await User.findOne({ username: username.toLowerCase().trim() });
        if (!user || !(await bcrypt.compare(password, user.passwordHash)))
            return res.status(401).json({ success: false, message: 'Bledny login lub haslo' });

        if (user.status === 'pending')
            return res.status(403).json({ success: false, message: 'Konto czeka na akceptacje druzynowego' });
        if (user.status === 'rejected')
            return res.status(403).json({ success: false, message: 'Konto zostalo odrzucone' });

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role, teamId: user.teamId, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true, token,
            user: { id: user._id, username: user.username, name: user.name, role: user.role, teamId: user.teamId }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Blad serwera: ' + err.message });
    }
});

// ================================================================
// DRUZYNY
// ================================================================

// Pobierz wszystkie druzyny (publiczny endpoint — potrzebny do rejestracji)
app.get('/api/teams', async (req, res) => {
    try {
        const teams = await Team.find({}, 'teamId name').sort({ name: 1 });
        res.json(teams);
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Dodaj nowa druzyne (tylko superadmin)
app.post('/api/teams', requireAuth, requireSuperAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim().length < 2)
            return res.status(400).json({ success: false, message: 'Podaj nazwe druzyny' });

        const teamId = 'druzyna_' + Date.now();
        const team = await Team.create({ teamId, name: name.trim() });
        res.json({ success: true, team });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Blad serwera' });
    }
});

// Usun druzyne (tylko superadmin) — usuwa tez wszystkich czlonkow i ich postepy
app.delete('/api/teams/:teamId', requireAuth, requireSuperAdmin, async (req, res) => {
    try {
        const team = await Team.findOne({ teamId: req.params.teamId });
        if (!team) return res.status(404).json({ error: 'Druzyna nie istnieje' });

        const members = await User.find({ teamId: req.params.teamId });
        for (const m of members) await Progress.deleteOne({ userId: m._id });
        await User.deleteMany({ teamId: req.params.teamId });
        await Team.deleteOne({ teamId: req.params.teamId });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// ================================================================
// UZYTKOWNICY
// ================================================================

// Czlonkowie druzyny
// Admin widzi tylko swoja druzyne, superadmin widzi wszystkich
app.get('/api/team-members', requireAuth, requireAdmin, async (req, res) => {
    try {
        const filter = req.user.role === 'superadmin'
            ? { role: { $ne: 'superadmin' } }
            : { teamId: req.user.teamId, role: { $ne: 'superadmin' } };
        const members = await User.find(filter, '-passwordHash').sort({ status: 1, name: 1 });
        res.json(members);
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Akceptuj konto
app.post('/api/users/:id/approve', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnien' });
        user.status = 'active';
        await user.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Odrzuc konto
app.post('/api/users/:id/reject', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnien' });
        user.status = 'rejected';
        await user.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Usun konto (admin: tylko swoja druzyna, superadmin: wszystkich)
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (user.role === 'superadmin')
            return res.status(403).json({ error: 'Nie mozna usunac super-admina' });
        if (user._id.toString() === req.user.id.toString())
            return res.status(400).json({ error: 'Nie mozesz usunac siebie' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnien' });

        await User.findByIdAndDelete(req.params.id);
        await Progress.deleteOne({ userId: req.params.id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// ================================================================
// POSTEPY
// ================================================================

app.get('/api/progress/:userId', requireAuth, async (req, res) => {
    try {
        if (req.user.role === 'user' && req.user.id.toString() !== req.params.userId)
            return res.status(403).json({ error: 'Brak uprawnien' });
        const p = await Progress.findOne({ userId: req.params.userId });
        res.json(p ? p.tasks : {});
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

app.post('/api/progress', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { userId, taskId, status } = req.body;
        if (req.user.role === 'admin') {
            const target = await User.findById(userId);
            if (!target || target.teamId !== req.user.teamId)
                return res.status(403).json({ error: 'Brak uprawnien' });
        }
        const key = 'tasks.' + taskId;
        const update = status ? { $set: { [key]: true } } : { $unset: { [key]: '' } };
        const p = await Progress.findOneAndUpdate({ userId }, update, { upsert: true, new: true });
        res.json({ success: true, progress: p.tasks });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Test czy serwer zyje
app.get('/api/ping', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.listen(PORT, () => console.log('Serwer port ' + PORT));

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
    role:         { type: String, enum: ['superadmin','ksis','instruktor','druzynowy','zastepowy','podzastepowy','user'], default: 'user' },
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

// Kolejnosc hierarchii — im nizszy indeks, tym wyzszy rang
const HIERARCHY = ['superadmin','ksis','instruktor','druzynowy','zastepowy','podzastepowy','user'];

function rankIndex(role) {
    var i = HIERARCHY.indexOf(role);
    return i === -1 ? 999 : i;
}

// Czy role A jest wyzsza od roli B?
function isHigherThan(roleA, roleB) {
    return rankIndex(roleA) < rankIndex(roleB);
}

// Czy ma uprawnienia do zarzadzania (ksis i wyzej)
function requireAdmin(req, res, next) {
    if (!['superadmin','ksis','instruktor','druzynowy','zastepowy'].includes(req.user.role))
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

        // Jesli nikt w druzynie nie ma rangi druzynowego lub wyzszej -> pierwszy user zostaje druzynowym
        const juzMaDruzynowego = await User.findOne({ teamId, role: { $in: ['ksis','instruktor','druzynowy'] }, status: 'active' });
        const role   = juzMaDruzynowego ? 'user'    : 'druzynowy';
        const status = juzMaDruzynowego ? 'pending' : 'active';

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

        // Pending i rejected mogą się zalogować - frontend pokaże odpowiedni ekran
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role, teamId: user.teamId, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true, token,
            user: { id: user._id, username: user.username, name: user.name, role: user.role, teamId: user.teamId, status: user.status }
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
            : { teamId: req.user.teamId };
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

// Zmien role uzytkownika
// Body: { newRole }
// Zasada: mozesz nadac tylko role NIZSZE od swojej wlasnej
//         nie mozesz zmieniac roli osob rownych lub wyzszych od siebie
app.post('/api/users/:id/promote', requireAuth, async (req, res) => {
    try {
        const { newRole } = req.body;
        if (!newRole) return res.status(400).json({ error: 'Podaj nowa role' });

        const validRoles = ['ksis','instruktor','druzynowy','zastepowy','podzastepowy','user'];
        if (!validRoles.includes(newRole) && req.user.role !== 'superadmin')
            return res.status(400).json({ error: 'Nieprawidlowa rola' });

        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (user.role === 'superadmin')
            return res.status(403).json({ error: 'Nie mozna zmienic roli super-admina' });

        // Sprawdz czy wykonujacy ma wyzsza range niz cel
        if (req.user.role !== 'superadmin') {
            if (!isHigherThan(req.user.role, user.role))
                return res.status(403).json({ error: 'Nie mozesz zmienic roli osoby o tej samej lub wyzszej randze' });
            // Sprawdz czy nadawana rola jest nizsza od nadajacego
            if (!isHigherThan(req.user.role, newRole))
                return res.status(403).json({ error: 'Mozesz nadac tylko role nizsze od swojej (' + req.user.role + ')' });
            // Sprawdz druzyne
            if (user.teamId !== req.user.teamId)
                return res.status(403).json({ error: 'Brak uprawnien do tej druzyny' });
        }

        user.role = newRole;
        if (user.status !== 'active') user.status = 'active';
        await user.save();
        res.json({ success: true, newRole: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Pobierz info o druzynie usera (nazwa druzyny)
app.get('/api/my-team', requireAuth, async (req, res) => {
    try {
        if (!req.user.teamId) return res.json({ teamName: null });
        const team = await Team.findOne({ teamId: req.user.teamId });
        res.json({ teamName: team ? team.name : null, teamId: req.user.teamId });
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
        const HIERARCHY = ['superadmin','ksis','instruktor','druzynowy','zastepowy','podzastepowy','user'];
        const myRank = HIERARCHY.indexOf(req.user.role);

        // Superadmin moze wszystko
        if (req.user.role !== 'superadmin') {
            const target = await User.findById(userId);
            if (!target) return res.status(404).json({ error: 'Uzytkownik nie istnieje' });

            // Sprawdz czy to wlasny progress
            const isSelf = target._id.toString() === req.user.id.toString();

            if (isSelf) {
                // Kadra moze zapisywac wlasny progress
                // (zastepowy, podzastepowy moga sobie zdawac - NIE, tylko user moze ogladac)
                // Zgodnie z wymaganiem: zastepowy NIE moze sobie zdawac
                const SELF_ALLOWED = ['ksis','instruktor','druzynowy'];
                if (!SELF_ALLOWED.includes(req.user.role)) {
                    return res.status(403).json({ error: 'Brak uprawnien do zapisu wlasnego progresu' });
                }
            } else {
                // Sprawdz hierarchie - mozna zdawac tylko nizszym
                const targetRank = HIERARCHY.indexOf(target.role);
                if (myRank >= targetRank) {
                    return res.status(403).json({ error: 'Mozna zdawac sprawnosci tylko osobom nizej w hierarchii' });
                }
                // Sprawdz ta sama druzyne (oprócz superadmina)
                if (String(target.teamId) !== String(req.user.teamId)) {
                    return res.status(403).json({ error: 'Brak uprawnien - inna druzyna' });
                }
            }
        }

        const key = 'tasks.' + taskId.replace(/[.]/g, '_');
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

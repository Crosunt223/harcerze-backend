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
    email:        { type: String, default: null },
    role:         { type: String, enum: ['superadmin','ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy','user'], default: 'user' },
    teamId:       { type: String, default: null },
    zastepId:     { type: String, default: null },
    status:       { type: String, enum: ['active','pending','rejected'], default: 'pending' }
}, { timestamps: true });

const progressSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, ref: 'User' },
    tasks:  { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

const Team     = mongoose.model('Team',     teamSchema);
const User     = mongoose.model('User',     userSchema);
const Progress = mongoose.model('Progress', progressSchema);

const zastepSchema = new mongoose.Schema({
    zastepId: { type: String, required: true, unique: true },
    name:     { type: String, required: true },
    teamId:   { type: String, required: false, default: null }
}, { timestamps: true });
const Zastep = mongoose.model('Zastep', zastepSchema);

const requestSchema = new mongoose.Schema({
    fromUserId:   { type: String, required: true },
    fromUserName: { type: String, required: true },
    toUserId:     { type: String, required: true },
    teamId:       { type: String, required: true },
    itemId:       { type: String, required: true },  // id sprawnosci/stopnia
    itemTitle:    { type: String },
    taskId:       { type: String, required: true },  // id konkretnego podpunktu
    taskText:     { type: String },                  // tekst podpunktu
    status:       { type: String, enum: ['pending','approved','rejected'], default: 'pending' }
}, { timestamps: true });
const SprawRequest = mongoose.model('SprawRequest', requestSchema);


const stopienSchema = new mongoose.Schema({
    userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    stopienId:   { type: String, required: true },  // st_1 .. st_6
    status:      { type: String, enum: ['open','closed'], default: 'open' },
    openedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    openedAt:    { type: Date },
    closedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    closedAt:    { type: Date },
}, { timestamps: true });
stopienSchema.index({ userId: 1, stopienId: 1 }, { unique: true });
const StopienStatus = mongoose.model('StopienStatus', stopienSchema);

const boardSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    slots:  { type: Array, default: Array(12).fill(null) }
}, { timestamps: true });
const Board = mongoose.model('Board', boardSchema);


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
const HIERARCHY = ['superadmin','ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy','user'];

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
    if (!['superadmin','ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy'].includes(req.user.role))
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
            name: name.trim(), role, teamId, status,
            email: (req.body.email || '').trim() || null
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
        const teams   = await Team.find({});
        const zastepy = await Zastep.find({});
        const membersWithInfo = members.map(m => {
            const obj = m.toObject();
            const t = teams.find(t => t.teamId === m.teamId);
            const z = zastepy.find(z => z.zastepId === m.zastepId);
            obj.teamName   = t ? t.name : m.teamId;
            obj.zastepName = z ? z.name : null;
            return obj;
        });
        res.json(membersWithInfo);
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

        const validRoles = ['ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy','user'];
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
        // Konwertuj na plain object (Mongoose Mixed moze zwrocic Map)
        const tasks = p ? (p.tasks ? Object.fromEntries(
            Object.entries(p.toObject().tasks || {})
        ) : {}) : {};
        res.json(tasks);
    } catch (err) {
        res.status(500).json({ error: 'Blad serwera' });
    }
});

app.post('/api/progress', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { userId, taskId, status } = req.body;
        const myRank = HIERARCHY.indexOf(req.user.role);

        if (req.user.role !== 'superadmin') {
            const target = await User.findById(userId);
            if (!target) return res.status(404).json({ error: 'Uzytkownik nie istnieje' });

            const isSelf = target._id.toString() === req.user.id.toString();
            const targetRank = HIERARCHY.indexOf(target.role);

            if (isSelf) {
                // zastepowy i podzastepowy NIE moga sobie zdawac
                const selfBlocked = ['zastepowy','podzastepowy','user'];
                if (selfBlocked.includes(req.user.role))
                    return res.status(403).json({ error: 'Brak uprawnien do zapisu wlasnego progresu' });
            } else {
                if (myRank >= targetRank)
                    return res.status(403).json({ error: 'Mozna zdawac tylko osobom nizej w hierarchii' });
                if (String(target.teamId) !== String(req.user.teamId))
                    return res.status(403).json({ error: 'Brak uprawnien - inna druzyna' });
            }
        }

        const safeTaskId = taskId.replace(/[.]/g, '_');
        const key = 'tasks.' + safeTaskId;
        const update = status ? { $set: { [key]: true } } : { $unset: { [key]: '' } };
        const p = await Progress.findOneAndUpdate({ userId }, update, { upsert: true, new: true });
        res.json({ success: true, progress: p.tasks });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Blad serwera' });
    }
});

// Test czy serwer zyje

// ── Zastepy ──────────────────────────────────────
app.get('/api/zastepy', requireAuth, async (req, res) => {
    try {
        let filter = {};
        if (req.user.role === 'superadmin') {
            const teamId = req.query.teamId || req.user.teamId;
            if (teamId) filter = { teamId };
            // bez teamId = zwróć wszystkie
        } else {
            filter = { teamId: req.user.teamId };
        }
        const zastepy = await Zastep.find(filter).sort({ name: 1 });
        res.json(zastepy);
    } catch (err) {
        console.error('GET /zastepy error:', err);
        res.status(500).json({ error: 'Blad serwera: ' + err.message });
    }
});

app.post('/api/zastepy', requireAuth, async (req, res) => {
    try {
        const allowed = ['superadmin','druzynowy','przyboczny'];
        if (!allowed.includes(req.user.role))
            return res.status(403).json({ error: 'Brak uprawnien' });
        const { name, teamId: bodyTeamId } = req.body;
        if (!name) return res.status(400).json({ error: 'Podaj nazwe zastepu' });
        const teamId = req.user.role === 'superadmin'
            ? (bodyTeamId || req.query.teamId || req.user.teamId)
            : req.user.teamId;
        if (!teamId) return res.status(400).json({ error: 'Podaj teamId dla superadmina' });
        const zastepId = 'z_' + teamId + '_' + Date.now();
        const z = await Zastep.create({ zastepId, name, teamId });
        res.json({ success: true, zastep: z });
    } catch (err) {
        console.error('POST /zastepy error:', err);
        res.status(500).json({ error: 'Blad serwera: ' + err.message });
    }
});

app.delete('/api/zastepy/:zastepId', requireAuth, async (req, res) => {
    try {
        const allowed = ['superadmin','druzynowy','przyboczny'];
        if (!allowed.includes(req.user.role))
            return res.status(403).json({ error: 'Brak uprawnien' });
        await Zastep.deleteOne({ zastepId: req.params.zastepId });
        await User.updateMany({ zastepId: req.params.zastepId }, { $set: { zastepId: null } });
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});

app.post('/api/users/:id/zastep', requireAuth, async (req, res) => {
    try {
        const allowed = ['superadmin','druzynowy','przyboczny'];
        if (!allowed.includes(req.user.role))
            return res.status(403).json({ error: 'Brak uprawnien' });
        const { zastepId } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { zastepId: zastepId || null }, { new: true });
        if (!user) return res.status(404).json({ error: 'Nie znaleziono usera' });
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});

app.get('/api/my-kadra', requireAuth, async (req, res) => {
    try {
        const myRank = HIERARCHY.indexOf(req.user.role);
        const kadra = await User.find({
            teamId: req.user.teamId,
            status: 'active',
            _id: { $ne: req.user.id }
        }, 'name role zastepId');
        const higher = kadra.filter(k => HIERARCHY.indexOf(k.role) < myRank);
        res.json(higher);
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});

// Wyslij prosbe o zdanie sprawnosci
app.post('/api/requests', requireAuth, async (req, res) => {
    try {
        const { toUserId, itemId, itemTitle, taskId, taskText } = req.body;
        if (!toUserId || !taskId) return res.status(400).json({ error: 'Brak danych' });
        const req2 = await SprawRequest.create({
            fromUserId:   req.user.id,
            fromUserName: req.user.name,
            toUserId,
            teamId:       req.user.teamId,
            itemId, itemTitle, taskId, taskText
        });
        res.json({ success: true, request: req2 });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});

// Pobierz prosby skierowane DO mnie (oczekujace)
app.get('/api/requests/incoming', requireAuth, async (req, res) => {
    try {
        const requests = await SprawRequest.find({ toUserId: req.user.id, status: 'pending' }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (err) { res.status(500).json({ error: 'Blad serwera' }); }
});

// Zatwierdz lub odrzuc prosbe
app.post('/api/requests/:id/respond', requireAuth, async (req, res) => {
    try {
        const { action } = req.body; // 'approve' lub 'reject'
        const request = await SprawRequest.findById(req.params.id);
        if (!request) return res.status(404).json({ error: 'Nie znaleziono' });
        if (request.toUserId !== req.user.id.toString())
            return res.status(403).json({ error: 'Brak uprawnien' });

        request.status = action === 'approve' ? 'approved' : 'rejected';
        await request.save();

        // Jesli zatwierdzone
        if (action === 'approve') {
            if (request.taskId === 'stopien-zaliczenie') {
                // Prośba o zaliczenie stopnia - otwórz stopień jeśli nie otwarty
                const stopienId = request.itemId;
                const existing = await StopienStatus.findOne({ userId: request.fromUserId, stopienId });
                if (!existing) {
                    await StopienStatus.create({
                        userId:    request.fromUserId,
                        stopienId,
                        status:    'open',
                        openedBy:  req.user.id,
                        openedAt:  new Date(),
                    });
                }
            } else {
                // Zwykłe zadanie sprawności - zapisz progress
                const safeTaskId = request.taskId.replace(/[.]/g, '_');
                await Progress.findOneAndUpdate(
                    { userId: request.fromUserId },
                    { $set: { ['tasks.' + safeTaskId]: true } },
                    { upsert: true, new: true }
                );
            }
        }
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});


// ── Tablica sprawnosci ──────────────────────────────
app.get('/api/board/:userId', requireAuth, async (req, res) => {
    try {
        const board = await Board.findOne({ userId: req.params.userId });
        const slots = board ? board.slots : Array(12).fill(null);
        res.json(slots);
    } catch (err) { res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});

app.post('/api/board/:userId', requireAuth, async (req, res) => {
    try {
        const userId = req.params.userId;
        const isOwn = userId === req.user.id.toString();
        const isAdmin = ['admin','druzynowy','przyboczny','superadmin'].includes(req.user.role);
        if (!isOwn && !isAdmin)
            return res.status(403).json({ error: 'Brak uprawnien' });

        let board = await Board.findOne({ userId });
        if (!board) board = new Board({ userId, slots: Array(12).fill(null) });

        // Obsługa obu formatów: { slots: [...] } lub { position, slot }
        if (Array.isArray(req.body.slots)) {
            board.slots = req.body.slots.slice(0, 12);
        } else {
            const { position, slot } = req.body;
            if (position >= 0 && position <= 11) {
                const slots = board.slots ? [...board.slots] : Array(12).fill(null);
                while (slots.length < 12) slots.push(null);
                slots[position] = slot || null;
                board.slots = slots;
            }
        }
        board.markModified('slots');
        await board.save();
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Blad serwera: ' + err.message }); }
});


// ── Stopnie ──────────────────────────────────────────────
// Pobierz statusy stopni dla usera
app.get('/api/stopnie/:userId', requireAuth, async (req, res) => {
    try {
        const statuses = await StopienStatus.find({ userId: req.params.userId });
        res.json(statuses);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// Otwórz stopień (druzynowy+)
app.post('/api/stopnie/:userId/open', requireAuth, async (req, res) => {
    try {
        const { stopienId } = req.body;
        const HIERARCHY = ['superadmin','ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy','user'];
        const myRank     = HIERARCHY.indexOf(req.user.role);
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
        const targetRank = HIERARCHY.indexOf(targetUser.role);

        // Tylko druzynowy (rank<=3) lub wyżej może otwierać
        if (myRank > 3 && req.user.role !== 'superadmin') {
            return res.status(403).json({ error: 'Brak uprawnień — tylko drużynowy lub wyżej' });
        }
        // Nie można otwierać osobie równej lub wyżej w hierarchii (poza superadmin)
        if (req.user.role !== 'superadmin' && myRank >= targetRank) {
            return res.status(403).json({ error: 'Brak uprawnień' });
        }

        // Sprawdź czy poprzedni stopień jest zamknięty
        const STOPNIE_ORDER = ['st_1','st_2','st_3','st_4','st_5','st_6'];
        const idx = STOPNIE_ORDER.indexOf(stopienId);
        if (idx > 0) {
            const prevId = STOPNIE_ORDER[idx - 1];
            const prev = await StopienStatus.findOne({ userId: req.params.userId, stopienId: prevId });
            if (!prev || prev.status !== 'closed') {
                return res.status(400).json({ error: 'Poprzedni stopień musi być zamknięty' });
            }
        }

        // Sprawdź czy już otwarty/zamknięty
        const existing = await StopienStatus.findOne({ userId: req.params.userId, stopienId });
        if (existing) return res.status(400).json({ error: 'Stopień już jest otwarty lub zamknięty' });

        const doc = await StopienStatus.create({
            userId:    req.params.userId,
            stopienId,
            status:    'open',
            openedBy:  req.user.id,
            openedAt:  new Date(),
        });
        res.json(doc);
    } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// Zamknij stopień (druzynowy+)
app.post('/api/stopnie/:userId/close', requireAuth, async (req, res) => {
    try {
        const { stopienId } = req.body;
        const HIERARCHY = ['superadmin','ksis','instruktor','druzynowy','przyboczny','zastepowy','podzastepowy','user'];
        const myRank     = HIERARCHY.indexOf(req.user.role);

        if (myRank > 3 && req.user.role !== 'superadmin') {
            return res.status(403).json({ error: 'Brak uprawnień' });
        }

        const doc = await StopienStatus.findOneAndUpdate(
            { userId: req.params.userId, stopienId, status: 'open' },
            { status: 'closed', closedBy: req.user.id, closedAt: new Date() },
            { new: true }
        );
        if (!doc) return res.status(404).json({ error: 'Stopień nie jest otwarty' });
        res.json(doc);
    } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});


// ================================================================
// LEGENDARNE SPRAWNOSCI
// ================================================================
const legendarySchema = new mongoose.Schema({
    itemId:    { type: String, required: true, unique: true },
    enabled:   { type: Boolean, default: false },
    threshold: { type: Number, default: 10 },
}, { timestamps: true });
const LegendarySpraw = mongoose.model('LegendarySpraw', legendarySchema);

app.get('/api/legendary', requireAuth, async (req, res) => {
    try { res.json(await LegendarySpraw.find({})); } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/legendary', requireAuth, async (req, res) => {
    try {
        if (!['superadmin'].includes(req.user.role)) return res.status(403).json({ error: 'Tylko superadmin' });
        const { itemId, enabled, threshold } = req.body;
        const doc = await LegendarySpraw.findOneAndUpdate({ itemId }, { enabled: !!enabled, threshold: threshold||10 }, { upsert: true, new: true });
        res.json(doc);
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/legendary-stats', requireAuth, async (req, res) => {
    try {
        const legendary = await LegendarySpraw.find({ enabled: true });
        if (!legendary.length) return res.json([]);
        const allProgress = await Progress.find({});
        const stats = legendary.map(function(leg) {
            let owners = 0;
            for (const p of allProgress) {
                const tasks = p.tasks || {};
                if (Object.keys(tasks).some(k => k.startsWith(leg.itemId + '-') && tasks[k])) owners++;
            }
            return { itemId: leg.itemId, threshold: leg.threshold, owners, active: owners >= 1 };
        });
        res.json(stats);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ================================================================
// PRYWATNE SPRAWNOSCI
// ================================================================
const privateSprawSchema = new mongoose.Schema({
    itemId:       { type: String, required: true, unique: true },
    title:        { type: String, required: true },
    category:     { type: String, default: 'Prywatne' },
    groups:       { type: Array, default: [] },
    images:       { type: Array, default: [] },
    allowedUsers: { type: Array, default: [] },
}, { timestamps: true });
const PrivateSpraw = mongoose.model('PrivateSpraw', privateSprawSchema);

app.get('/api/private-spraw', requireAuth, async (req, res) => {
    try {
        const uid = req.user.id.toString();
        const items = req.user.role === 'superadmin'
            ? await PrivateSpraw.find({})
            : await PrivateSpraw.find({ allowedUsers: uid });
        res.json(items);
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/private-spraw/all', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Tylko superadmin' });
        res.json(await PrivateSpraw.find({}));
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/private-spraw', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Tylko superadmin' });
        const { itemId, title, category, groups, images, allowedUsers } = req.body;
        if (!title) return res.status(400).json({ error: 'Brak tytulu' });
        const id = itemId || ('priv_' + Date.now().toString(36));
        const doc = await PrivateSpraw.findOneAndUpdate({ itemId: id }, { title, category: category||'Prywatne', groups: groups||[], images: images||[], allowedUsers: allowedUsers||[] }, { upsert: true, new: true });
        res.json(doc);
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/private-spraw/:itemId', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Tylko superadmin' });
        await PrivateSpraw.deleteOne({ itemId: req.params.itemId });
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ================================================================
// ZGLOSZENIA BLEDOW
// ================================================================
const bugReportSchema = new mongoose.Schema({
    fromUserId:   { type: String, required: true },
    fromUserName: { type: String, required: true },
    fromRole:     { type: String },
    description:  { type: String, required: true },
    screenshot:   { type: String, default: null },
    status:       { type: String, enum: ['new','read','resolved'], default: 'new' },
}, { timestamps: true });
const BugReport = mongoose.model('BugReport', bugReportSchema);

app.post('/api/bug-report', requireAuth, async (req, res) => {
    try {
        const { description, screenshot } = req.body;
        if (!description) return res.status(400).json({ error: 'Podaj opis bledu' });
        const doc = await BugReport.create({ fromUserId: req.user.id, fromUserName: req.user.name, fromRole: req.user.role, description, screenshot: screenshot||null });
        res.json({ success: true, id: doc._id });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/bug-reports', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        res.json(await BugReport.find({}).sort({ createdAt: -1 }));
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/bug-reports/:id/status', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        const doc = await BugReport.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        if (!doc) return res.status(404).json({ error: 'Nie znaleziono' });
        res.json(doc);
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/bug-reports/:id', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        await BugReport.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});


// Usun konto
app.post('/api/delete-account', requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Podaj haslo' });
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(403).json({ error: 'Nieprawidlowe haslo' });
        // Usun postep, board, zgloszenia
        await Progress.deleteMany({ userId: req.user.id });
        await Board.deleteMany({ userId: req.user.id });
        await StopienStatus.deleteMany({ userId: req.user.id });
        await SprawRequest.deleteMany({ $or: [{ fromUserId: req.user.id }, { toUserId: req.user.id }] });
        await user.deleteOne();
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/my-zastep', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id, 'zastepId');
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        res.json({ zastepId: user.zastepId || null });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ping', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.listen(PORT, () => console.log('Serwer port ' + PORT));
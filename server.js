/*
 * ================================================================
 *  SERWER HARCERSKI — MongoDB + Express
 * ================================================================
 *
 *  ZMIENNE ŚRODOWISKOWE (Render.com → Environment):
 *    MONGODB_URI  — np. mongodb+srv://user:pass@cluster.mongodb.net/harcerze
 *    JWT_SECRET   — dowolny długi losowy ciąg
 *
 *  npm install express cors body-parser mongoose bcryptjs jsonwebtoken
 *
 *  KONTO SUPER-ADMINA tworzone automatycznie:
 *    login: admin  |  hasło: admin
 * ================================================================
 */

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
const JWT_SECRET  = process.env.JWT_SECRET  || 'zmien_mnie_na_renderze';
const PORT        = process.env.PORT        || 3000;

// ================================================================
//  POŁĄCZENIE Z MONGODB
// ================================================================

mongoose.connect(MONGODB_URI)
    .then(() => { console.log('✅ MongoDB połączone'); seedSuperAdmin(); })
    .catch(err => console.error('❌ MongoDB błąd:', err));

// ================================================================
//  MODELE
// ================================================================

/*
 *  Team — drużyna harcerska
 */
const Team = mongoose.model('Team', new mongoose.Schema({
    teamId: { type: String, required: true, unique: true },
    name:   { type: String, required: true }
}, { timestamps: true }));

/*
 *  User — konto użytkownika
 *
 *  role:
 *    'superadmin' — konto admin/admin, widzi wszystkich, może usuwać
 *    'admin'      — drużynowy, zarządza tylko swoją drużyną
 *    'user'       — harcerz, tylko odczyt własnego profilu
 *
 *  status:
 *    'pending'  — czeka na akceptację admina
 *    'active'   — może się logować
 *    'rejected' — odrzucony przez admina
 */
const User = mongoose.model('User', new mongoose.Schema({
    username:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    name:         { type: String, required: true },
    role:         { type: String, enum: ['superadmin','admin','user'], default: 'user' },
    teamId:       { type: String, default: null },
    status:       { type: String, enum: ['active','pending','rejected'], default: 'pending' }
}, { timestamps: true }));

/*
 *  Progress — postępy harcerza
 *  tasks = { "st_1-0-1": true, "historyk-0-2": true, ... }
 */
const Progress = mongoose.model('Progress', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, ref: 'User' },
    tasks:  { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true }));

// ================================================================
//  SEED — super-admin + domyślne drużyny
// ================================================================

async function seedSuperAdmin() {
    // Domyślne drużyny
    const defaultTeams = [
        { teamId: 'team_las',  name: 'Leśne Skrzaty' },
        { teamId: 'team_woda', name: 'Wodne Wilki'    }
    ];
    for (const t of defaultTeams) {
        await Team.findOneAndUpdate({ teamId: t.teamId }, t, { upsert: true });
    }

    // Super-admin (tylko jeśli nie istnieje)
    if (await User.findOne({ username: 'admin' })) {
        console.log('ℹ️  Super-admin już istnieje');
        return;
    }
    await User.create({
        username:     'admin',
        passwordHash: await bcrypt.hash('admin', 10),
        name:         'Super Admin',
        role:         'superadmin',
        teamId:       null,
        status:       'active'
    });
    console.log('✅ Utworzono super-admina (login: admin, hasło: admin)');
}

// ================================================================
//  MIDDLEWARE AUTH
// ================================================================

/*
 *  requireAuth — sprawdza JWT z nagłówka Authorization: Bearer <token>
 *  Dokłada req.user = { id, username, role, teamId, name }
 */
function requireAuth(req, res, next) {
    const header = req.headers['authorization'];
    if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokenu' });
    try {
        req.user = jwt.verify(header.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token wygasł lub jest nieprawidłowy' });
    }
}

function requireAdmin(req, res, next) {
    if (!['admin','superadmin'].includes(req.user.role)) return res.status(403).json({ error: 'Brak uprawnień' });
    next();
}

// ================================================================
//  ENDPOINTY AUTH
// ================================================================

/*
 *  POST /api/register
 *  Body: { username, password, name, teamId }
 *
 *  Logika roli:
 *  - Jeśli nikt w drużynie nie ma roli 'admin' → rejestrujący zostaje adminem (active)
 *  - W przeciwnym razie → 'user' ze statusem 'pending'
 */
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name, teamId } = req.body;

        if (!username || !password || !name || !teamId)
            return res.status(400).json({ success: false, message: 'Wszystkie pola są wymagane' });
        if (username.length < 3)
            return res.status(400).json({ success: false, message: 'Login musi mieć minimum 3 znaki' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Hasło musi mieć minimum 6 znaków' });

        if (await User.findOne({ username: username.toLowerCase() }))
            return res.status(400).json({ success: false, message: 'Ten login jest już zajęty' });

        const team = await Team.findOne({ teamId });
        if (!team)
            return res.status(400).json({ success: false, message: 'Drużyna nie istnieje' });

        // Czy drużyna ma już aktywnego admina?
        const hasAdmin = await User.findOne({ teamId, role: 'admin', status: 'active' });
        const role   = hasAdmin ? 'user'    : 'admin';
        const status = hasAdmin ? 'pending' : 'active';

        await User.create({
            username: username.toLowerCase(),
            passwordHash: await bcrypt.hash(password, 10),
            name, role, teamId, status
        });

        res.json({
            success: true,
            message: role === 'admin'
                ? `Zostałeś adminem drużyny "${team.name}"! Możesz się zalogować.`
                : 'Konto utworzone! Czeka na akceptację drużynowego.'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Błąd serwera' });
    }
});

/*
 *  POST /api/login
 *  Body: { username, password }
 *  Zwraca JWT token ważny 7 dni.
 */
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ success: false, message: 'Podaj login i hasło' });

        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.passwordHash)))
            return res.status(401).json({ success: false, message: 'Błędny login lub hasło' });

        if (user.status === 'pending')
            return res.status(403).json({ success: false, message: 'Konto czeka na akceptację drużynowego' });
        if (user.status === 'rejected')
            return res.status(403).json({ success: false, message: 'Konto zostało odrzucone' });

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
        res.status(500).json({ success: false, message: 'Błąd serwera' });
    }
});

// ================================================================
//  ENDPOINTY DRUŻYN
// ================================================================

// GET /api/teams — lista drużyn do formularza rejestracji (publiczny)
app.get('/api/teams', async (req, res) => {
    try {
        res.json(await Team.find({}, 'teamId name'));
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

// ================================================================
//  ENDPOINTY UŻYTKOWNIKÓW
// ================================================================

/*
 *  GET /api/team-members
 *  Admin → widzi tylko swoją drużynę.
 *  Superadmin → widzi wszystkich (oprócz innych superadminów).
 */
app.get('/api/team-members', requireAuth, requireAdmin, async (req, res) => {
    try {
        const filter = req.user.role === 'superadmin'
            ? { role: { $ne: 'superadmin' } }
            : { teamId: req.user.teamId, role: { $ne: 'superadmin' } };
        const members = await User.find(filter, '-passwordHash').sort({ status: 1, name: 1 });
        res.json(members);
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

// POST /api/users/:id/approve — akceptacja konta
app.post('/api/users/:id/approve', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnień do tej drużyny' });

        user.status = 'active';
        await user.save();
        res.json({ success: true, message: `Konto ${user.name} aktywowane` });
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

// POST /api/users/:id/reject — odrzucenie konta
app.post('/api/users/:id/reject', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnień do tej drużyny' });

        user.status = 'rejected';
        await user.save();
        res.json({ success: true, message: `Konto ${user.name} odrzucone` });
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

/*
 *  DELETE /api/users/:id — usunięcie konta + postępów
 *  Admin: tylko w swojej drużynie.
 *  Superadmin: wszystkich (poza sobą i innymi superadminami).
 */
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Nie znaleziono' });
        if (user.role === 'superadmin')
            return res.status(403).json({ error: 'Nie można usunąć super-admina' });
        if (user._id.toString() === req.user.id.toString())
            return res.status(400).json({ error: 'Nie możesz usunąć własnego konta' });
        if (req.user.role === 'admin' && user.teamId !== req.user.teamId)
            return res.status(403).json({ error: 'Brak uprawnień do tej drużyny' });

        await User.findByIdAndDelete(req.params.id);
        await Progress.deleteOne({ userId: req.params.id });
        res.json({ success: true, message: `Konto ${user.name} usunięte` });
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

// ================================================================
//  ENDPOINTY POSTĘPÓW
// ================================================================

// GET /api/progress/:userId
app.get('/api/progress/:userId', requireAuth, async (req, res) => {
    try {
        if (req.user.role === 'user' && req.user.id.toString() !== req.params.userId)
            return res.status(403).json({ error: 'Brak uprawnień' });

        const progress = await Progress.findOne({ userId: req.params.userId });
        res.json(progress ? progress.tasks : {});
    } catch { res.status(500).json({ error: 'Błąd serwera' }); }
});

/*
 *  POST /api/progress
 *  Body: { userId, taskId, status }
 *  Tylko admin/superadmin może zmieniać postępy.
 */
app.post('/api/progress', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { userId, taskId, status } = req.body;

        if (req.user.role === 'admin') {
            const target = await User.findById(userId);
            if (!target || target.teamId !== req.user.teamId)
                return res.status(403).json({ error: 'Brak uprawnień do tego użytkownika' });
        }

        const update = status
            ? { $set:   { [`tasks.${taskId}`]: true } }
            : { $unset: { [`tasks.${taskId}`]: ''   } };

        const progress = await Progress.findOneAndUpdate(
            { userId },
            update,
            { upsert: true, new: true }
        );
        res.json({ success: true, progress: progress.tasks });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Błąd serwera' });
    }
});

// ================================================================
//  START
// ================================================================

app.listen(PORT, () => console.log(`🚀 Serwer na porcie ${PORT}`));

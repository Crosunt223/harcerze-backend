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
    itemId:       { type: String, required: true },  
    itemTitle:    { type: String },
    taskId:       { type: String, required: true },  
    taskText:     { type: String },                  
    status:       { type: String, enum: ['pending','approved','rejected'], default: 'pending' }
}, { timestamps: true });
const SprawRequest = mongoose.model('SprawRequest', requestSchema);

const bugReportSchema = new mongoose.Schema({
    userId:   { type: String, required: true },
    username: { type: String, required: true },
    text:     { type: String, required: true },
    status:   { type: String, enum: ['nowe','w_trakcie','zamkniete'], default: 'nowe' }
}, { timestamps: true });
const BugReport = mongoose.model('BugReport', bugReportSchema);

// ================================================================
// MIDDLEWARE AUTH
// ================================================================

function requireAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Brak tokena' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// ================================================================
// TRASY (ROUTES)
// ================================================================

app.get('/api/teams', async (req, res) => {
    try {
        const teams = await Team.find({});
        res.json(teams);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name, teamId } = req.body;
        const exists = await User.findOne({ username: username.toLowerCase() });
        if (exists) return res.status(400).json({ message: 'Login zajety' });

        const hash = await bcrypt.hash(password, 10);
        const newUser = new User({
            username: username.toLowerCase(),
            passwordHash: hash,
            name,
            teamId,
            status: 'pending'
        });
        await newUser.save();
        res.json({ message: 'Zarejestrowano. Poczekaj na akceptacje.' });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) return res.status(401).json({ message: 'Bledny login lub haslo' });

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ message: 'Bledny login lub haslo' });

        const token = jwt.sign({ userId: user._id, username: user.username, role: user.role, teamId: user.teamId }, JWT_SECRET);
        res.json({ token, user: { id: user._id, username: user.username, name: user.name, role: user.role, status: user.status, teamId: user.teamId } });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// Zgłoś błąd (Poprawione/Dodane)
app.post('/api/bug-reports', requireAuth, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) return res.status(400).json({ error: 'Brak treści zgłoszenia' });
        const bug = new BugReport({
            userId: req.user.userId,
            username: req.user.username,
            text: text,
            status: 'nowe'
        });
        await bug.save();
        res.json({ success: true, bug });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pobierz wszystkie zgloszenia (tylko superadmin)
app.get('/api/bug-reports', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        const docs = await BugReport.find({}).sort({ createdAt: -1 });
        res.json(docs);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// Zmien status (tylko superadmin)
app.post('/api/bug-reports/:id/status', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        const { status } = req.body;
        const doc = await BugReport.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!doc) return res.status(404).json({ error: 'Nie znaleziono' });
        res.json(doc);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// Usun zgloszenie (tylko superadmin)
app.delete('/api/bug-reports/:id', requireAuth, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Brak uprawnien' });
        await BugReport.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// SEEDER DRUŻYN
async function seedData() {
    const count = await Team.countDocuments();
    if (count === 0) {
        await Team.create([
            { teamId: 'test_team', name: 'Próbna Drużyna' }
        ]);
        console.log('Seeded initial data');
    }
}

app.listen(PORT, () => console.log('Server running on port ' + PORT));
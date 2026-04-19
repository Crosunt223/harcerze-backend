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

mongoose.connect(MONGODB_URI)
    .then(() => { console.log('MongoDB OK'); })
    .catch(err => console.error('MongoDB BLAD:', err));

const userSchema = new mongoose.Schema({
    username:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    name:         { type: String, required: true },
    role:         { type: String, enum: ['harcerz', 'zastepowy', 'druzynowy', 'ksis', 'superadmin'], default: 'harcerz' },
    zastepId:     { type: String, default: null },
    sprawnosci:   [{
        sprawnoscId: String,
        status: { type: String, enum: ['niepodjęta', 'realizowana', 'ukończona', 'zatwierdzona'], default: 'niepodjęta' },
        level: Number,
        updatedBy: String
    }]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Brak tokena' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Bledny token' });
        req.user = decoded;
        next();
    });
};

// POPRAWIONY ENDPOINT ZMIANY STATUSU Z BLOKADA KSI
app.post('/api/users/:userId/sprawnosci/:sprId/status', requireAuth, async (req, res) => {
    try {
        const { userId, sprId } = req.params;
        const { status, level } = req.body; // level przesylany z frontu dla weryfikacji
        
        const targetUser = await User.findById(userId);
        if (!targetUser) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });

        // Sprawdzenie czy to sprawnosc 3* lub 4*
        if (level >= 3) {
            if (req.user.role !== 'superadmin' && req.user.role !== 'ksis') {
                return res.status(403).json({ error: 'Tylko KSI lub Admin może zarządzać sprawnościami 3* i 4*' });
            }
        }

        const sprIndex = targetUser.sprawnosci.findIndex(s => s.sprawnoscId === sprId);
        if (sprIndex === -1) {
            targetUser.sprawnosci.push({ sprawnoscId: sprId, status, level, updatedBy: req.user.name });
        } else {
            targetUser.sprawnosci[sprIndex].status = status;
            targetUser.sprawnosci[sprIndex].updatedBy = req.user.name;
        }

        await targetUser.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Pozostale endpointy (uproszczone na potrzeby pliku)
app.listen(PORT, () => console.log('Server running on port ' + PORT));

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Książeczka Harcerska Online</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { --p: #2e7d32; --p-dark: #1b3a28; --bg: #f7f9f5; --card: #ffffff; --text: #2c3e50; }
        body { margin: 0; font-family: sans-serif; background: var(--bg); color: var(--text); display: flex; height: 100vh; }
        
        #loginOverlay { position: fixed; inset: 0; background: linear-gradient(135deg, var(--p-dark), var(--p)); display: flex; justify-content: center; align-items: center; z-index: 1000; }
        .login-box { background: white; padding: 40px; border-radius: 20px; width: 320px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .login-box input, .login-box select { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; }
        .login-box button { width: 100%; padding: 12px; background: var(--p); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; }
        .toggle-link { color: var(--p); cursor: pointer; text-decoration: underline; font-size: 0.9rem; margin-top: 10px; display: block; }
        
        .sidebar { width: 280px; background: var(--card); border-right: 1px solid #ddd; display: flex; flex-direction: column; }
        .brand { padding: 20px; background: var(--p); color: white; text-align: center; }
        .nav-list { flex: 1; overflow-y: auto; list-style: none; padding: 0; margin: 0; }
        .nav-item { padding: 15px; border-bottom: 1px solid #eee; cursor: pointer; transition: 0.2s; }
        .nav-item:hover { background: #f0f0f0; }

        .main { flex: 1; padding: 40px; overflow-y: auto; }
        .card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .logout-btn { position: fixed; bottom: 20px; left: 20px; padding: 10px; background: var(--p); color: white; border: none; border-radius: 5px; cursor: pointer; z-index: 10; }
        
        .loading-text { font-size: 0.8rem; color: #666; margin-top: 5px; display: none; }
    </style>
</head>
<body>

<div id="loginOverlay">
    <div class="login-box">
        <h2 id="title">Czuwaj!</h2>
        <input type="text" id="userInp" placeholder="Login">
        <input type="password" id="passInp" placeholder="Hasło">
        
        <div id="regExtra" style="display:none;">
            <input type="text" id="nameInp" placeholder="Twoje Imię i Nazwisko">
            <select id="teamSelect"><option value="">Wybierz drużynę...</option></select>
            <div id="loadingTeams" class="loading-text">Budzenie serwera (może to zająć chwilę)...</div>
        </div>

        <button onclick="handleAuth()" id="btnAction">Zaloguj się</button>
        <span class="toggle-link" onclick="toggleMode()" id="toggleTxt">Brak konta? Zarejestruj się</span>
    </div>
</div>

<button class="logout-btn" onclick="logout()">Wyloguj 🚪</button>

<nav class="sidebar">
    <div class="brand"><h3>HARC-APP</h3><small id="userDisplay"></small></div>
    <ul class="nav-list" id="navList"></ul>
</nav>

<main class="main" id="contentArea">
    <div class="card">Wybierz coś z menu po lewej, aby zobaczyć zadania.</div>
</main>

<script src="stopnie.js"></script>
<script src="sprawnosci.js"></script>

<script>
    // --- POPRAWIONY ADRES ---
    // Musi zawierać /api na końcu, bo tak zdefiniowaliśmy routing w server.js
    const API = 'https://harcerze-backend.onrender.com/api';
    
    let user = null;
    let isReg = false;
    let db = [];

    window.onload = () => {
        // Ładowanie bazy z plików
        db = [
            ...(typeof stopnieData !== 'undefined' ? stopnieData : []),
            ...(typeof sprawnosciData !== 'undefined' ? sprawnosciData : [])
        ];
        
        const saved = sessionStorage.getItem('harc_session');
        if (saved) {
            user = JSON.parse(saved);
            initDashboard();
        }
    };

    async function toggleMode() {
        isReg = !isReg;
        document.getElementById('regExtra').style.display = isReg ? 'block' : 'none';
        document.getElementById('title').innerText = isReg ? 'Rejestracja' : 'Czuwaj!';
        document.getElementById('btnAction').innerText = isReg ? 'Zarejestruj' : 'Zaloguj';
        document.getElementById('toggleTxt').innerText = isReg ? 'Masz konto? Zaloguj' : 'Brak konta? Zarejestruj';
        
        if (isReg) {
            const loadingMsg = document.getElementById('loadingTeams');
            loadingMsg.style.display = 'block';
            try {
                // To wywoła: https://harcerze-backend.onrender.com/api/teams
                const res = await fetch(`${API}/teams`);
                if (!res.ok) throw new Error("Błąd sieci");
                const teams = await res.json();
                
                document.getElementById('teamSelect').innerHTML = teams.map(t => `<option value="${t.id}">${t.name}</option>`).join('');
                loadingMsg.style.display = 'none';
            } catch (e) {
                console.error(e);
                loadingMsg.innerText = "Serwer śpi lub zły adres. Poczekaj 30s i spróbuj ponownie.";
                // Fallback, żeby użytkownik wiedział co się dzieje
                document.getElementById('teamSelect').innerHTML = '<option>Błąd połączenia</option>';
            }
        }
    }

    async function handleAuth() {
        const username = document.getElementById('userInp').value;
        const password = document.getElementById('passInp').value;
        
        if (isReg) {
            const name = document.getElementById('nameInp').value;
            const teamId = document.getElementById('teamSelect').value;
            if(!name || !teamId) return alert("Uzupełnij imię i drużynę!");

            try {
                const res = await fetch(`${API}/register`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, password, name, teamId })
                });
                const data = await res.json();
                alert(data.message);
                if(data.success) toggleMode();
            } catch (e) { alert("Błąd połączenia z serwerem."); }

        } else {
            try {
                const res = await fetch(`${API}/login`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                
                if (res.ok) {
                    user = data.user;
                    sessionStorage.setItem('harc_session', JSON.stringify(user));
                    document.getElementById('loginOverlay').style.display = 'none';
                    document.getElementById('userDisplay').innerText = user.name;
                    initDashboard();
                } else {
                    alert(data.message);
                }
            } catch(e) {
                alert("Błąd logowania. Serwer Render może być w trakcie budzenia się (zajmuje to ok. 1 minuty).");
            }
        }
    }

    function initDashboard() {
        renderSidebar();
        if (user.role === 'admin') renderAdmin();
        else renderUser();
    }

    function renderSidebar() {
        const list = document.getElementById('navList');
        list.innerHTML = '';
        db.forEach(item => {
            const li = document.createElement('li');
            li.className = 'nav-item';
            li.innerText = item.title;
            li.onclick = () => loadTasks(item.id);
            list.appendChild(li);
        });
    }

    async function loadTasks(id) {
        const item = db.find(x => x.id === id);
        // Pobierz postęp
        const res = await fetch(`${API}/progress/${user.id}`);
        const progress = await res.json();

        let html = `<h2>${item.title}</h2>`;
        item.groups.forEach((g, gIdx) => {
            html += `<div class="card"><h4>${g.name}</h4>`;
            g.tasks.forEach((t, tIdx) => {
                const taskId = `${id}-${gIdx}-${tIdx}`;
                const checked = progress[taskId] ? 'checked' : '';
                html += `
                <label style="display:block; margin:8px 0;">
                    <input type="checkbox" ${checked} onchange="saveProgress('${taskId}', this.checked)"> ${t}
                </label>`;
            });
            html += `</div>`;
        });
        document.getElementById('contentArea').innerHTML = html;
    }

    async function saveProgress(taskId, status) {
        await fetch(`${API}/progress`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user.id, taskId, status })
        });
    }

    async function renderAdmin() {
        const res = await fetch(`${API}/pending-requests?adminId=${user.id}`);
        const pending = await res.json();
        let html = `<h2>Panel Drużynowego</h2>`;
        
        if (pending.length > 0) {
            html += `<div class="card"><h3>Oczekujące prośby:</h3>`;
            pending.forEach(p => {
                html += `<div style="margin-bottom:10px; display:flex; justify-content:space-between;">
                    <span>👤 ${p.name}</span>
                    <button onclick="approve(${p.id})">Zaakceptuj</button>
                </div>`;
            });
            html += `</div>`;
        } else {
            html += `<div class="card">Brak nowych próśb o dołączenie.</div>`;
        }
        document.getElementById('contentArea').innerHTML = html;
    }

    async function approve(uid) {
        await fetch(`${API}/approve-user`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ adminId: user.id, userId: uid })
        });
        renderAdmin();
    }

    function renderUser() {
        document.getElementById('contentArea').innerHTML = `
            <h2>Witaj, ${user.name}!</h2>
            <div class="card">Twoje konto jest aktywne. Wybierz sprawności z menu.</div>
        `;
    }

    function logout() { sessionStorage.clear(); location.reload(); }
</script>
</body>
</html>

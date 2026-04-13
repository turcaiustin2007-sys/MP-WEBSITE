import jwt   from 'jsonwebtoken';
import fs    from 'fs';
import path  from 'path';
import admin from 'firebase-admin';

const JWT_SECRET = process.env.JWT_SECRET;

// ── Firebase Admin init (o singură dată) ─────────────────────────────────────
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId:   process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            // Vercel stochează newline-urile ca \n literal în env vars
            privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        }),
    });
}

function parseCookie(header, name) {
    if (!header) return null;
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(req, res) {
    // ── 1. Cookie prezent? ────────────────────────────────────────────────────
    const token = parseCookie(req.headers.cookie, 'ocs_admin');
    if (!token) {
        console.warn('[admin] No cookie — redirect to /');
        return res.redirect('/');
    }

    // ── 2. JWT valid? ─────────────────────────────────────────────────────────
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET, { issuer: 'ocs-portal' });
    } catch(err) {
        console.warn('[admin] Invalid/expired JWT:', err.message);
        res.setHeader('Set-Cookie', 'ocs_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    // ── 3. Are rang suficient? ────────────────────────────────────────────────
    if (!payload.isAdmin && !payload.isHighCommand && !payload.isDeveloper && !payload.isInstructor) {
        console.warn('[admin] No valid rank:', payload.roblox);
        res.setHeader('Set-Cookie', 'ocs_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    // ── 4. Generează Firebase custom token ────────────────────────────────────
    let firebaseToken = null;
    try {
        // uid-ul trebuie să fie string — folosim roblox ID sau roblox name
        const uid = String(payload.id || payload.roblox);
        firebaseToken = await admin.auth().createCustomToken(uid, {
            isAdmin:       payload.isAdmin       || false,
            isHighCommand: payload.isHighCommand || false,
            isDeveloper:   payload.isDeveloper   || false,
        });
    } catch(err) {
        // Nu blocăm pagina dacă Firebase Admin eșuează,
        // dar logăm eroarea ca să o putem depana
        console.error('[admin] Firebase custom token error:', err.message);
    }

    // ── 5. Servim HTML-ul ─────────────────────────────────────────────────────
    try {
        const htmlPath = path.join(process.cwd(), '_admin_template.html');
        const html     = fs.readFileSync(htmlPath, 'utf8');

        const safePayload = JSON.stringify({
            id:            payload.id,
            roblox:        payload.roblox,
            isInstructor:  payload.isInstructor  || false,
            isAdmin:       payload.isAdmin       || false,
            isHighCommand: payload.isHighCommand || false,
            isDeveloper:   payload.isDeveloper   || false,
            firebaseToken: firebaseToken,          // acum generat server-side
            exp:           payload.exp
        });

        const injected = html.replace(
            '/* __SERVER_PAYLOAD__ */',
            `window.__SERVER_PAYLOAD__ = ${safePayload};`
        );

        res.setHeader('Content-Type',           'text/html; charset=utf-8');
        res.setHeader('Cache-Control',          'no-store, no-cache, must-revalidate, private');
        res.setHeader('X-Frame-Options',        'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.status(200).send(injected);
    } catch(e) {
        console.error('[admin] Failed to read _admin_template.html:', e);
        res.status(500).send('Internal Server Error');
    }
}

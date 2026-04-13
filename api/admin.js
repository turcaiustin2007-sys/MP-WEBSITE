import jwt   from 'jsonwebtoken';
import fs    from 'fs';
import path  from 'path';
import admin from 'firebase-admin';

const JWT_SECRET = process.env.JWT_SECRET;

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId:   process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: (process.env.FIREBASE_PRIVATE_KEY || '')
            .replace(/\\n/g, '\n')
            .replace(/^"|"$/g, ''),
        }),
    });
}

function parseCookie(header, name) {
    if (!header) return null;
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(req, res) {
    const token = parseCookie(req.headers.cookie, 'ocs_admin');
    if (!token) return res.redirect('/');

    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET, { issuer: 'ocs-portal' });
    } catch(err) {
        res.setHeader('Set-Cookie', 'ocs_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    if (!payload.isAdmin && !payload.isHighCommand && !payload.isDeveloper) {
        res.setHeader('Set-Cookie', 'ocs_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    let firebaseToken = null;
    try {
        const uid = String(payload.id || payload.roblox);
        firebaseToken = await admin.auth().createCustomToken(uid, {
            admin:       payload.isAdmin       || false,
            highCommand: payload.isHighCommand || false,
            developer:   payload.isDeveloper   || false,
        });
    } catch(err) {
        console.error('[admin] Firebase custom token error:', err.message);
    }

    try {
        const htmlPath = path.join(process.cwd(), '_admin_template.html');
        const html     = fs.readFileSync(htmlPath, 'utf8');

        const safePayload = JSON.stringify({
            id:            payload.id,
            roblox:        payload.roblox,
            isAdmin:       payload.isAdmin       || false,
            isHighCommand: payload.isHighCommand || false,
            isDeveloper:   payload.isDeveloper   || false,
            firebaseToken: firebaseToken,
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

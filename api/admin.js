import jwt  from 'jsonwebtoken';
import fs   from 'fs';
import path from 'path';

const JWT_SECRET = process.env.JWT_SECRET;

function parseCookie(header, name) {
    if (!header) return null;
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

export default function handler(req, res) {

    // ── 1. Cookie present? ────────────────────────────────────────────────────
    const token = parseCookie(req.headers.cookie, 'mp_admin');
    if (!token) {
        console.warn('[MP admin] No cookie — redirect');
        return res.redirect('/');
    }

    // ── 2. JWT valid? ─────────────────────────────────────────────────────────
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET, { issuer: 'mp-portal' });
    } catch(err) {
        console.warn('[MP admin] Invalid JWT:', err.message);
        res.setHeader('Set-Cookie', 'mp_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    // ── 3. Has valid access? ──────────────────────────────────────────────────
    if (!payload.isAdmin && !payload.isGuest) {
        console.warn('[MP admin] No valid access:', payload.roblox);
        res.setHeader('Set-Cookie', 'mp_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
        return res.redirect('/');
    }

    // ── 4. Serve HTML with injected payload ───────────────────────────────────
    try {
        const htmlPath = path.join(process.cwd(), '_admin_template.html');
        const html     = fs.readFileSync(htmlPath, 'utf8');

        const safePayload = JSON.stringify({
            id:            payload.id,
            roblox:        payload.roblox,
            isAdmin:       payload.isAdmin       || false,
            isHighCommand: payload.isHighCommand || false,
            isGuest:       payload.isGuest       || false,
            grantAccess:   payload.grantAccess   || null,
            firebaseToken: payload.firebaseToken || null,
            exp:           payload.exp
        });

        const injected = html.replace(
            '/* __SERVER_PAYLOAD__ */',
            `window.__SERVER_PAYLOAD__ = ${safePayload};`
        );

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.status(200).send(injected);

    } catch(e) {
        console.error('[MP admin] Failed to read _admin_template.html:', e);
        res.status(500).send('Internal Server Error');
    }
}

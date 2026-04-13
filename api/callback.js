import admin from 'firebase-admin';
import jwt   from 'jsonwebtoken';

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId:   process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey:  process.env.FIREBASE_PRIVATE_KEY
                ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
                : undefined
        })
    });
}

const JWT_SECRET = process.env.JWT_SECRET;

function parseCookie(header, name) {
    if (!header) return null;
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(req, res) {
    const { code, state } = req.query;

    // ── 1. Validare CSRF state ────────────────────────────────────────────────
    const cookieState = parseCookie(req.headers.cookie, 'oauth_state');
    res.setHeader('Set-Cookie', 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');

    if (!cookieState || !state || cookieState !== state || !state.startsWith('ocs_')) {
        console.warn('State mismatch:', { cookieState, queryState: state });
        return res.redirect('/?error=invalid_state');
    }

    if (!code) return res.redirect('/?error=auth_failed');

    const clientId     = process.env.ROBLOX_CLIENT_ID;
    const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

    if (!clientId || !clientSecret || !JWT_SECRET) {
        console.error('FATAL: Missing env vars');
        return res.redirect('/?error=server_config_error');
    }

    const protocol    = req.headers['x-forwarded-proto'] || 'https';
    const host        = req.headers.host;
    const redirectUri = `${protocol}://${host}/api/callback`;

    try {
        // ── 2. Token Roblox ───────────────────────────────────────────────────
        const tokenRes = await fetch('https://apis.roblox.com/oauth/v1/token', {
            method:  'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id:     clientId,
                client_secret: clientSecret,
                grant_type:    'authorization_code',
                code,
                redirect_uri:  redirectUri
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenRes.ok) {
            console.error('Roblox token error:', tokenData);
            throw new Error('Token Roblox failed');
        }

        // ── 3. UserInfo ───────────────────────────────────────────────────────
        const userRes  = await fetch('https://apis.roblox.com/oauth/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userRes.json();
        if (!userRes.ok) throw new Error('UserInfo Roblox failed');

        // ── 4. Verificare grupuri ─────────────────────────────────────────────
        //
        //  Grup 254403   (RIC principal)
        //    rank >= 87  → Warrant Officer — poate da examen
        //
        //  Grup 811677186  (Staff OCS)
        //  Grup 811677186  (Staff OCS)
        //    rank 10     → Instructor (isInstructor) — Officer Registry only
        //    rank 15     → Interviewer (isAdmin)
        //    rank >= 254 → Academy Head (isHighCommand)
        //
        //  Grup 747852578  (Developeri)
        //    rank 255    → Developer (toate drepturile)

        const RIC_GROUP_ID   = 254403;
        const STAFF_GROUP_ID = 811677186;
        const DEV_GROUP_ID   = 747852578;

        let isWO          = false;
        let isInstructor  = false;
        let isAdmin       = false;
        let isHighCommand = false;
        let isDeveloper   = false;

        const groupsRes = await fetch(
            `https://groups.roblox.com/v1/users/${userData.sub}/groups/roles`,
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
        );
        if (!groupsRes.ok) {
            console.warn('Groups API non-OK');
            return res.redirect('/?error=group_check_failed');
        }

        const groupsData = await groupsRes.json();

        // LOG pentru debug în Vercel Logs
        console.log(`[callback] ${userData.preferred_username} | groups:`,
            groupsData.data.map(g => `${g.group.id}:rank${g.role.rank}`).join(' | ')
        );

        for (const g of groupsData.data) {
            // Grup RIC: WO = rank 87 sau mai mare
            if (g.group.id === RIC_GROUP_ID) {
                if (g.role.rank === 175) isWO = true;
            }

            // Grup Staff OCS
            if (g.group.id === STAFF_GROUP_ID) {
                if (g.role.rank >= 10)  isInstructor  = true;
                if (g.role.rank >= 15)  isAdmin       = true;
                if (g.role.rank >= 254) isHighCommand = true;
            }

            // Grup dev: rank exact 255
            if (g.group.id === DEV_GROUP_ID && g.role.rank >= 255) {
                isDeveloper   = true;
                isAdmin       = true;
                isHighCommand = true;
                isInstructor  = true;
                isWO          = true;
            }
        }

        console.log(`[callback] ${userData.preferred_username} | isWO:${isWO} isInstructor:${isInstructor} isAdmin:${isAdmin} isHighCommand:${isHighCommand} isDeveloper:${isDeveloper}`);

        // ── 5. Firebase Custom Token (admini + instructors) ───────────────────
        let firebaseToken = null;
        if (isAdmin || isInstructor || isDeveloper) {
            try {
                firebaseToken = await admin.auth().createCustomToken(String(userData.sub), {
                    admin: isAdmin, highCommand: isHighCommand, developer: isDeveloper, instructor: isInstructor
                });
            } catch(e) { console.error('Firebase token error:', e); }
        }

        // ── 6. JWT semnat ─────────────────────────────────────────────────────
        const jwtPayload = {
            id: userData.sub,
            roblox: userData.preferred_username,
            isWO, isInstructor, isAdmin, isHighCommand, isDeveloper, firebaseToken
        };
        const token = jwt.sign(jwtPayload, JWT_SECRET, {
            expiresIn: '2h',
            issuer:    'ocs-portal'
        });

        // ── 7. Rutare ─────────────────────────────────────────────────────────
        if (isAdmin || isInstructor || isDeveloper) {
            res.setHeader('Set-Cookie',
                `ocs_admin=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Max-Age=7200; Path=/`
            );
            return res.redirect('/api/admin');
        }

        // WO sau fără rang → portal candidat
        return res.redirect(`/?token=${token}`);

    } catch(error) {
        console.error('Callback handler error:', error);
        return res.redirect('/?error=server_error');
    }
}

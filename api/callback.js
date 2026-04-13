import admin from 'firebase-admin';
import jwt   from 'jsonwebtoken';

/**
 * Inițializare Firebase Admin SDK
 * Se asigură că aplicația nu este inițializată de mai multe ori în mediul serverless (Vercel).
 */
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

/**
 * Utilitar pentru extragerea cookie-urilor din header
 */
function parseCookie(header, name) {
    if (!header) return null;
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(req, res) {
    const { code, state } = req.query;

    // ── 1. VALIDARE CSRF STATE ────────────────────────────────────────────────
    const cookieState = parseCookie(req.headers.cookie, 'oauth_state');
    res.setHeader('Set-Cookie', 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');

    if (!cookieState || !state || cookieState !== state || !state.startsWith('ocs_')) {
        console.warn('[AUTH] State mismatch detected:', { cookieState, queryState: state });
        return res.redirect('/?error=invalid_state');
    }

    if (!code) {
        console.error('[AUTH] No authorization code provided by Roblox');
        return res.redirect('/?error=auth_failed');
    }

    const clientId     = process.env.ROBLOX_CLIENT_ID;
    const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

    if (!clientId || !clientSecret || !JWT_SECRET) {
        console.error('FATAL: Missing environment variables');
        return res.redirect('/?error=server_config_error');
    }

    const protocol    = req.headers['x-forwarded-proto'] || 'https';
    const host        = req.headers.host;
    const redirectUri = `${protocol}://${host}/api/callback`;

    try {
        // ── 2. SCHIMBĂ CODUL PENTRU TOKEN ROBLOX ─────────────────────────────
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
            console.error('[ROBLOX] Token exchange failed:', tokenData);
            throw new Error('Token Roblox failed');
        }

        // ── 3. PREIA DATELE UTILIZATORULUI ──────────────────────────────────
        const userRes  = await fetch('https://apis.roblox.com/oauth/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userRes.json();
        if (!userRes.ok) throw new Error('UserInfo Roblox failed');

        // ── 4. CONFIGURARE GRUP ȘI RANGURI ──────────────────────────────────
        const MP_GROUP_ID  = 328843; 
        const DEV_GROUP_ID = 747852578;

        // Gradele care pot da EXAMENUL (CANDIDAȚI)
        const MP_ELIGIBLE_EXAM_RANKS = [50, 100, 150]; 

        // Definire permisiuni (Instructor a fost eliminat)
        let isEligibleCandidate = false;
        let isAdmin             = false;
        let isHighCommand       = false;
        let isDeveloper         = false;

        const groupsRes = await fetch(
            `https://groups.roblox.com/v1/users/${userData.sub}/groups/roles`,
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
        );
        
        if (!groupsRes.ok) {
            console.error('[ROBLOX] Groups API error');
            return res.redirect('/?error=group_check_failed');
        }

        const groupsData = await groupsRes.json();

        for (const g of groupsData.data) {
            if (g.group.id === MP_GROUP_ID) {
                const rank = g.role.rank;

                // Verificare Candidat
                if (MP_ELIGIBLE_EXAM_RANKS.includes(rank)) {
                    isEligibleCandidate = true;
                }

                // Verificare Staff MP (fără instructor)
                if (rank >= 240) {
                    isAdmin = true;
                    isHighCommand = true;
                }
            }

            // Verificare Grup Developer
            if (g.group.id === DEV_GROUP_ID && g.role.rank >= 255) {
                isDeveloper         = true;
                isAdmin             = true;
                isHighCommand       = true;
                isEligibleCandidate = true;
            }
        }

        // ── 5. FIREBASE CUSTOM TOKEN (PENTRU ADMINI) ─────────────────────────
        let firebaseToken = null;
        if (isAdmin || isDeveloper) {
            try {
                firebaseToken = await admin.auth().createCustomToken(String(userData.sub), {
                    admin: isAdmin, 
                    highCommand: isHighCommand, 
                    developer: isDeveloper
                });
            } catch(e) { 
                console.error('[FIREBASE] Error creating custom token:', e); 
            }
        }

        // ── 6. GENERARE JWT PENTRU FRONTEND ──────────────────────────────────
        const jwtPayload = {
            id: userData.sub,
            roblox: userData.preferred_username,
            isMP: isEligibleCandidate,
            isAdmin, 
            isHighCommand, 
            isDeveloper, 
            firebaseToken
        };

        const token = jwt.sign(jwtPayload, JWT_SECRET, {
            expiresIn: '2h',
            issuer:    'ocs-portal'
        });

        // ── 7. REDIRECȚIONARE FINALĂ ─────────────────────────────────────────
        if (isAdmin || isDeveloper) {
            res.setHeader('Set-Cookie',
                `ocs_admin=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Max-Age=7200; Path=/`
            );
            return res.redirect('/api/admin');
        }

        return res.redirect(`/?token=${token}`);

    } catch(error) {
        console.error('[FATAL] Callback handler error:', error);
        return res.redirect('/?error=server_error');
    }
}

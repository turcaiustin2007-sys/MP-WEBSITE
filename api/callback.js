import admin from 'firebase-admin';
import jwt   from 'jsonwebtoken';

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId:   process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey:  process.env.FIREBASE_PRIVATE_KEY
                ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/^"|"$/g, '')
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

    // ── 1. CSRF state validation ──────────────────────────────────────────────
    const cookieState = parseCookie(req.headers.cookie, 'oauth_state');
    res.setHeader('Set-Cookie', 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');

    if (!cookieState || !state || cookieState !== state || !state.startsWith('mp_')) {
        console.warn('[MP callback] State mismatch:', { cookieState, queryState: state });
        return res.redirect('/?error=invalid_state');
    }

    if (!code) return res.redirect('/?error=auth_failed');

    const clientId     = process.env.ROBLOX_CLIENT_ID;
    const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

    if (!clientId || !clientSecret || !JWT_SECRET) {
        console.error('[MP callback] Missing env vars');
        return res.redirect('/?error=server_config_error');
    }

    const protocol    = req.headers['x-forwarded-proto'] || 'https';
    const host        = req.headers.host;
    const redirectUri = `${protocol}://${host}/api/callback`;

    try {
        // ── 2. Exchange code for token ────────────────────────────────────────
        const tokenRes = await fetch('https://apis.roblox.com/oauth/v1/token', {
            method:  'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: clientId, client_secret: clientSecret,
                grant_type: 'authorization_code', code, redirect_uri: redirectUri
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenRes.ok) throw new Error('Roblox token exchange failed');

        // ── 3. Get user info ──────────────────────────────────────────────────
        const userRes  = await fetch('https://apis.roblox.com/oauth/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userRes.json();
        if (!userRes.ok) throw new Error('Roblox userinfo failed');

        // ── 4. Check Roblox group ranks ───────────────────────────────────────
        //
        //  Group 328843 (Military Police)
        //    rank 50, 100, 150  → eligible to take the exam (isEligible)
        //    rank 240           → isAdmin  (MP CPT — examiner)
        //    rank 250           → isHighCommand (MP COM — academy head)

        const MP_GROUP_ID = 254403;

        let isEligible    = false;
        let isAdmin       = false;
        let isHighCommand = false;

        const groupsRes = await fetch(
            `https://groups.roblox.com/v1/users/${userData.sub}/groups/roles`,
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
        );
        if (!groupsRes.ok) return res.redirect('/?error=group_check_failed');

        const groupsData = await groupsRes.json();

        console.log(`[MP callback] ${userData.preferred_username} | groups:`,
            groupsData.data.map(g => `${g.group.id}:rank${g.role.rank}`).join(' | ')
        );

        for (const g of groupsData.data) {
            if (g.group.id === MP_GROUP_ID) {
                const rank = g.role.rank;
                if ([50, 100, 125].includes(rank)) isEligible    = true;
                if (rank >= 255) {
                    isAdmin = true;
                    isHighCommand = true;
            }
        }
    }

        console.log(`[MP callback] ${userData.preferred_username} | isEligible:${isEligible} isAdmin:${isAdmin} isHighCommand:${isHighCommand}`);

        // ── 5. Check Access Grants (for non-staff, non-eligible users) ────────
        // MP COM can grant specific people temporary access to DB / Evals / History
        let isGuest     = false;
        let grantAccess = null;

        if (!isEligible && !isAdmin) {
            try {
                const grantSnap = await admin.firestore()
                    .collection('mp_access_grants')
                    .where('roblox', '==', userData.preferred_username)
                    .limit(1)
                    .get();

                if (!grantSnap.empty) {
                    const grant = grantSnap.docs[0].data();
                    const now   = new Date();

                    // Check expiry — null means no expiry
                    const expired = grant.expiresAt && new Date(grant.expiresAt) < now;

                    if (!expired) {
                        isGuest     = true;
                        grantAccess = grant.access || { db: false, evals: false, history: false };
                        console.log(`[MP callback] ${userData.preferred_username} has guest grant:`, grantAccess);
                    } else {
                        console.log(`[MP callback] ${userData.preferred_username} grant expired`);
                    }
                }
            } catch(e) {
                console.error('[MP callback] Grant check error:', e);
            }
        }

        // ── 6. Firebase token (staff + guests) ───────────────────────────────
        let firebaseToken = null;
        if (isAdmin || isGuest) {
            try {
                firebaseToken = await admin.auth().createCustomToken(String(userData.sub), {
                    admin: isAdmin, highCommand: isHighCommand, guest: isGuest
                });
            } catch(e) { console.error('[MP callback] Firebase token error:', e); }
        }

        // ── 7. Sign JWT ───────────────────────────────────────────────────────
        const jwtPayload = {
            id: userData.sub,
            roblox: userData.preferred_username,
            isEligible, isAdmin, isHighCommand,
            isGuest, grantAccess,
            firebaseToken
        };

        const token = jwt.sign(jwtPayload, JWT_SECRET, {
            expiresIn: '2h',
            issuer:    'mp-portal'
        });

        // ── 8. Route ──────────────────────────────────────────────────────────
        if (isAdmin || isGuest) {
            res.setHeader('Set-Cookie',
                `mp_admin=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Max-Age=7200; Path=/`
            );
            return res.redirect('/api/admin');
        }

        if (isEligible) {
            return res.redirect(`/?token=${token}`);
        }

        // Not eligible and no grant → redirect to / with token (will show ACCESS DENIED)
        return res.redirect(`/?token=${token}`);

    } catch(error) {
        console.error('[MP callback] Error:', error);
        return res.redirect('/?error=server_error');
    }
}

import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

/**
 * POST /api/verify-token
 * Body: { token: string, requireAdmin: boolean }
 * Răspuns: { valid: true, payload } sau { valid: false, error }
 *
 * Folosit de admin.html la load pentru a valida token-ul
 * fără a expune JWT_SECRET în browser.
 */
export default function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { token, requireAdmin = false } = req.body ?? {};

    if (!token) {
        return res.status(400).json({ valid: false, error: 'Token lipsă' });
    }

    if (!JWT_SECRET) {
        console.error('JWT_SECRET lipsă din env');
        return res.status(500).json({ valid: false, error: 'Server config error' });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET, {
            issuer:   'ocs-portal',
            // audience se poate adăuga dacă știi exact host-ul
        });

        if (requireAdmin && !payload.isAdmin && !payload.isHighCommand && !payload.isDeveloper) {
            return res.status(403).json({ valid: false, error: 'Insufficient permissions' });
        }

        // Nu re-trimite firebaseToken înapoi — e deja în browser din redirect
        const { firebaseToken: _stripped, ...safePayload } = payload;

        return res.status(200).json({ valid: true, payload: safePayload });

    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ valid: false, error: 'Token expirat. Te rog re-autentifică-te.' });
        }
        return res.status(401).json({ valid: false, error: 'Token invalid' });
    }
}

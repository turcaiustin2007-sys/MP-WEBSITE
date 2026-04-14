import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

export default function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { token, requireAdmin = false } = req.body ?? {};
    if (!token) return res.status(400).json({ valid: false, error: 'Token missing' });
    if (!JWT_SECRET) return res.status(500).json({ valid: false, error: 'Server config error' });

    try {
        const payload = jwt.verify(token, JWT_SECRET, { issuer: 'mp-portal' });

        if (requireAdmin && !payload.isAdmin && !payload.isGuest) {
            return res.status(403).json({ valid: false, error: 'Insufficient permissions' });
        }

        const { firebaseToken: _stripped, ...safePayload } = payload;
        return res.status(200).json({ valid: true, payload: safePayload });

    } catch(err) {
        if (err.name === 'TokenExpiredError')
            return res.status(401).json({ valid: false, error: 'Token expired. Please re-authenticate.' });
        return res.status(401).json({ valid: false, error: 'Invalid token' });
    }
}

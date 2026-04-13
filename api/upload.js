import jwt from 'jsonwebtoken';

const JWT_SECRET       = process.env.JWT_SECRET;
const UPLOAD_SECRET    = process.env.UPLOAD_SECRET;     // secret partajat cu Apps Script
const GOOGLE_SCRIPT_URL = process.env.GOOGLE_SCRIPT_URL; // URL-ul Apps Script în .env, nu în client

/**
 * POST /api/upload
 * Header: Authorization: Bearer <jwt>
 * Body: multipart/form-data cu câmpul "file"
 *
 * Proxy securizat: clientul nu știe URL-ul Apps Script și nu poate
 * accesa endpoint-ul fără un JWT valid.
 */
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // ── 1. Verifică JWT ────────────────────────────────────────────────────────
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        jwt.verify(authHeader.slice(7), JWT_SECRET, { issuer: 'ocs-portal' });
    } catch {
        return res.status(401).json({ error: 'Token invalid sau expirat' });
    }

    // ── 2. Verifică dimensiunea (5MB max) ────────────────────────────────────
    const contentLength = parseInt(req.headers['content-length'] ?? '0');
    if (contentLength > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Fișier prea mare. Max 5MB.' });
    }

    if (!GOOGLE_SCRIPT_URL || !UPLOAD_SECRET) {
        console.error('GOOGLE_SCRIPT_URL sau UPLOAD_SECRET lipsesc din env');
        return res.status(500).json({ error: 'Server config error' });
    }

    // ── 3. Colectează body-ul raw și îl redirecționează spre Apps Script ──────
    try {
        // Parsează body-ul din request (Vercel îl pune în req.body ca string dacă e urlencoded)
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const rawBody = Buffer.concat(chunks).toString();

        const params = new URLSearchParams(rawBody);
        params.append('secret', UPLOAD_SECRET); // adaugă secretul server-side

        const scriptRes = await fetch(GOOGLE_SCRIPT_URL, {
            method:  'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body:    params
        });

        const resultUrl = await scriptRes.text();

        if (!resultUrl.startsWith('http')) {
            throw new Error(`Apps Script error: ${resultUrl}`);
        }

        return res.status(200).json({ url: resultUrl });

    } catch (err) {
        console.error('Upload proxy error:', err);
        return res.status(500).json({ error: 'Upload eșuat. Încearcă din nou.' });
    }
}

// Dezactivează parsarea automată a body-ului de către Vercel
export const config = { api: { bodyParser: false } };

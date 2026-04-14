import crypto from 'crypto';

export default function handler(req, res) {
    const clientId    = process.env.ROBLOX_CLIENT_ID;
    const protocol    = req.headers['x-forwarded-proto'] || 'https';
    const host        = req.headers.host;
    const redirectUri = encodeURIComponent(`${protocol}://${host}/api/callback`);

    const state = 'mp_' + crypto.randomBytes(16).toString('hex');

    res.setHeader('Set-Cookie',
        `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/`
    );

    const robloxAuthUrl =
        `https://apis.roblox.com/oauth/v1/authorize` +
        `?client_id=${clientId}` +
        `&redirect_uri=${redirectUri}` +
        `&scope=openid%20profile` +
        `&response_type=code` +
        `&state=${state}`;

    res.redirect(robloxAuthUrl);
}

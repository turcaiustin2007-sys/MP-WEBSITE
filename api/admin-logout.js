export default function handler(req, res) {
    res.setHeader('Set-Cookie', 'mp_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
    res.redirect('/');
}

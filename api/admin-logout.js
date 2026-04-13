export default function handler(req, res) {
    res.setHeader('Set-Cookie', 'ocs_admin=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
    res.redirect('/');
}

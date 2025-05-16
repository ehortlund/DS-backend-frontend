module.exports = async (req, res) => {
    console.log('Anrop till api/redirect.js mottaget...');
    console.log('Metod:', req.method);
    console.log('Headers:', req.headers);

    // Hämta token från cookie
    const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
    }, {}) : {};
    const token = cookies.token;
    console.log('Token från cookie:', token);

    if (!token) {
        console.log('Ingen token hittades, omdirigerar till login.html');
        res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
        res.setHeader('Location', '/login.html');
        return res.status(307).end();
    }

    // Om token finns, låt Vercel fortsätta med nästa route
    return res.status(200).end();
};
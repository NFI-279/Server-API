require('dotenv').config();
const express = require("express");

const publicRoutes = require('./routes/public');
const protectedRoutes = require('./routes/protected');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json({
    verify: (req, res, buf) => {
        if (buf && buf.length) {
            req.rawBody = buf.toString('utf8');
        }
    }
}));


app.set('trust proxy', 1);

app.use('/api/v1/public', publicRoutes);
app.use('/api/v1/secure', protectedRoutes);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

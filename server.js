const express = require('express')
//const exphbs  = require('express-handlebars')
const app = express()
const bycrypt = require('bcryptjs')
const passport = require('passport')
const initializePassport = require('./passport-config')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const jwt = require('jsonwebtoken')

initializePassport(passport, email => users.find(user => user.email === email), id => users.find(user => user.id === id))
const users = []

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
//app.engine('handlebars', exphbs())
app.set('view-engine', 'ejs')

app.use(flash())
app.use(session({
    secret: 'my_secret_key',
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

let user = {
    id: '1',
    email: 'Johndoe@gmail.com',
    password: '123456'
};

const JWT_SECRET = 'some super secret...'

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/");
    }
    next();
}

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

app.post('/signup', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bycrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        console.log(users);
        res.redirect('/login')
    } catch (e) {
        console.log(e);
        res.redirect('/signup')
    }
})

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

app.get('/signup', checkNotAuthenticated, (req, res) => {
    res.render('signup.ejs')
})

app.delete('/logout', (req, res) => {
    req.logout(req.user, err => {
        if (err) return next(err)
        res.redirect('/')
        console.log({ message: 'User logged out' });

    })
})

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password.ejs');
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const user = users.find(user => user.email === email);

    if (!user) {
        return res.send('User not found');
    }

    const secret = JWT_SECRET + user.password;
    const payload = {
        email: user.email,
        id: user.id,
    };
    const token = jwt.sign(payload, secret, { expiresIn: '15m' })
    const link = `http://localhost:3000/reset-password/${user.id}/${token}`
    console.log(link);
    res.send('Email sent');
});

app.get('/reset-password/:id/:token', (req, res) => {
    const { id, token } = req.params;
    const user = users.find(user => user.id === id);

    if (!user) {
        return res.send('Invalid id');
    }

    const secret = JWT_SECRET + user.password;
    try {
        const payload = jwt.verify(token, secret);
        res.render('reset-password.ejs', { email: user.email, token });
    } catch (error) {
        console.log(error);
        res.send(error.message);
    }
});

app.post('/reset-password/:id/:token', (req, res) => {
    const { id, token } = req.params;
    const { password, password2 } = req.body;

    const user = users.find(user => user.id === id);

    if (!user) {
        return res.send('Invalid id');
    }

    if (password !== password2) {
        return res.send('Passwords do not match');
    }

    const secret = JWT_SECRET + user.password;
    try {
        const payload = jwt.verify(token, secret);
        user.password = password;
        res.send('Password reset successful');
    } catch (error) {
        console.log(error.message);
        res.send(error.message);
    }
});



function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}

app.listen(3000, () => {
    console.log('Server is running on port 3000...');
});

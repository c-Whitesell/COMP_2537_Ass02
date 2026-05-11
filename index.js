require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.set('view engine', 'ejs');

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const client = new MongoClient(process.env.MONGO_URI);
let users;

async function connectDB() {
  await client.connect();
  const db = client.db();
  users = db.collection('users');
  console.log('Connected to MongoDB');
}
connectDB();

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      crypto: {
        secret: process.env.MONGODB_SESSION_SECRET,
      },
    }),
    cookie: { maxAge: expireTime },
    resave: false,
    saveUninitialized: false,
  }),
);

function isLoggedIn(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect('/login');
  }
  next();
}

function isAdmin(req, res, next) {
  if (!req.session.authenticated || req.session.user_type !== 'admin') {
    res.status(403);
    return res.render('unauthorized', {
      name: req.session.name || undefined,
    });
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.render('index', { name: req.session.name });
  } else {
    res.render('index');
  }
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required(),
  });

  const validation = schema.validate({ name, email, password });
  if (validation.error) {
    const errorMessage =
      validation.error.details[0].context.label === 'name'
        ? 'Please provide a name.'
        : validation.error.details[0].context.label === 'email'
          ? 'Please provide an email address.'
          : 'Please provide a password.';
    return res.render('signup', { error: errorMessage });
  }

  const existingUser = await users.findOne({ email });
  if (existingUser) {
    return res.render('signup', {
      error: 'User with that email already exists.',
    });
  }

  const hash = await bcrypt.hash(password, 10);
  await users.insertOne({
    name,
    email,
    password: hash,
    user_type: 'user',
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = 'user';

  res.redirect('/members');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/loggingin', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate({ email, password });
  if (validation.error) {
    return res.render('login', { error: 'Please provide email and password.' });
  }

  const user = await users.findOne({ email });
  if (!user) {
    return res.render('login', {
      error: 'User and password combination not found.',
    });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.render('login', {
      error: 'User and password combination not found.',
    });
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = email;
  req.session.user_type = user.user_type || 'user';

  res.redirect('/members');
});

app.get('/members', isLoggedIn, (req, res) => {
  const images = ['img1.png', 'img2.png', 'img3.png'];
  res.render('members', { name: req.session.name, images });
});

app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
  const allUsers = await users.find({}).toArray();
  res.render('admin', { name: req.session.name, users: allUsers });
});

app.post('/promote/:email', isLoggedIn, isAdmin, async (req, res) => {
  const userEmail = req.params.email;

  const schema = Joi.object({
    email: Joi.string().email().required(),
  });

  const validation = schema.validate({ email: userEmail });
  if (validation.error) {
    return res.status(400).send('Invalid email format');
  }

  await users.updateOne({ email: userEmail }, { $set: { user_type: 'admin' } });

  res.redirect('/admin');
});

app.post('/demote/:email', isLoggedIn, isAdmin, async (req, res) => {
  const userEmail = req.params.email;

  const schema = Joi.object({
    email: Joi.string().email().required(),
  });

  const validation = schema.validate({ email: userEmail });
  if (validation.error) {
    return res.status(400).send('Invalid email format');
  }

  await users.updateOne({ email: userEmail }, { $set: { user_type: 'user' } });

  res.redirect('/admin');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

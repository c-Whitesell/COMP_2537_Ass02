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
    // store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
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

app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.send(`
      <h1>Hello ${req.session.name}</h1>
      <a href="/members">Members Area</a><br>
      <a href="/logout">Logout</a>
    `);
  } else {
    res.send(`
      <h1>Home</h1>
      <a href="/signup">Signup</a><br>
      <a href="/login">Login</a>
    `);
  }
});

app.get('/signup', (req, res) => {
  res.send(`
    <h1>Signup</h1>
    <form action='/signup' method='post'>
      <input name='name' placeholder='Name'><br>
      <input name='email' placeholder='Email'><br>
      <input name='password' type='password' placeholder='Password'><br>
      <button>Signup</button>
    </form>
  `);
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
    return res.send('Invalid input');
  }

  const hash = await bcrypt.hash(password, 10);

  await users.insertOne({ name, email, password: hash });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  res.redirect('/members');
});

app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form action='/loggingin' method='post'>
      <input name='email' placeholder='Email'><br>
      <input name='password' type='password' placeholder='Password'><br>
      <button>Login</button>
    </form>
  `);
});

app.post('/loggingin', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate({ email, password });
  if (validation.error) {
    return res.redirect('/login');
  }

  const user = await users.findOne({ email });

  if (!user) {
    return res.send('User not found');
  }

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.send('Invalid password');
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = email;

  res.redirect('/members');
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) return res.redirect('/');

  const images = ['img1.png', 'img2.png', 'img3.png'];
  const random = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello ${req.session.name}</h1>
    <img src="/images/${random}" width="300"/><br>
    <a href="/logout">Logout</a>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.status(404).send('Page not found');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

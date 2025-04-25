# full-stack-project-
full stack
{
  "name": "movie",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "start": "node server.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "description": ""
}

const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ msg: 'Invalid token' });
  }
};
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

userSchema.pre('save', async function () {
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

router.post('/register', async (req, res) => {
  try {
    const user = await User.create(req.body);
    res.status(201).json({ msg: 'User created' });
  } catch {
    res.status(400).json({ msg: 'User already exists' });
  }
});

router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || !(await user.comparePassword(req.body.password))) {
    return res.status(401).json({ msg: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Movie = require('../models/Movie');

router.post('/', auth, async (req, res) => {
  const movie = await Movie.create({ ...req.body, user: req.user.id });
  res.status(201).json(movie);
});

router.get('/', auth, async (req, res) => {
  const filter = { user: req.user.id };
  if (req.query.genre) filter.genre = req.query.genre;
  if (req.query.watched) filter.watched = req.query.watched === 'true';

  const movies = await Movie.find(filter);
  res.json(movies);
});

router.patch('/:id', auth, async (req, res) => {
  const movie = await Movie.findOneAndUpdate(
    { _id: req.params.id, user: req.user.id },
    req.body,
    { new: true }
  );
  if (!movie) return res.status(404).json({ msg: 'Not found' });
  res.json(movie);
});

router.delete('/:id', auth, async (req, res) => {
  const movie = await Movie.findOneAndDelete({ _id: req.params.id, user: req.user.id });
  if (!movie) return res.status(404).json({ msg: 'Not found' });
  res.json({ msg: 'Deleted' });
});

module.exports = router;
const mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
  title: String,
  genre: String,
  year: Number,
  watched: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

module.exports = mongoose.model('Movie', movieSchema);



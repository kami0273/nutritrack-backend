import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
 
dotenv.config();
 
const app = express();
 
// ── Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));
 
// ── User Schema
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  profile:  { type: Object, default: {} }
});
const User = mongoose.model('User', userSchema);
 
// ── Auth Middleware (protects private routes)
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
 
app.use(cors({
  origin: "https://nutritrackai.vercel.app",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]  // added Authorization
}));
 
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
 
// ── Register
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email already in use' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash });
    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
// ── Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email, profile: user.profile });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
// ── Save profile (called after onboarding)
app.post('/user/profile', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { profile: req.body });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
// ── Get profile
app.get('/user/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user.profile);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
// ── Analyze (your existing route, unchanged)
app.post('/analyze', async (req, res) => {
  try {
    console.log(req.body);
 
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
 
    const data = await response.json();
 
    if (!response.ok) {
      console.log("API ERROR:", data);
      return res.status(response.status).json({
        error: data.error?.message || 'API error'
      });
    }
 
    const text = data.content?.[0]?.text || "No response";
 
    res.json({
      content: [{ text }]
    });
 
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
const PORT = process.env.PORT || 3000;
 
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
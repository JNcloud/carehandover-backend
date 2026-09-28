require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// Połączenie z Supabase za pomocą klucza z pliku .env
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Middleware sprawdzający token autoryzacji
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Brak tokenu autoryzacji' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Nieprawidłowy lub wygasły token' });
    req.user = user;
    next();
  });
}

// ENDPOINT 1: Logowanie opiekuna
app.post('/api/v1/auth/login', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: 'Wymagany jest adres email' });

  const { data: user, error } = await supabase
    .from('staff_users')
    .select('*')
    .eq('email', email)
    .eq('is_active', true)
    .single();

  if (error || !user) {
    return res.status(401).json({ error: 'Nie znaleziono aktywnego opiekuna' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ token, user: { id: user.id, name: user.full_name, role: user.role } });
});

// ENDPOINT 2: Pobranie listy mieszkańców
app.get('/api/v1/residents', authenticateToken, async (req, res) => {
  const { data: residents, error } = await supabase
    .from('residents')
    .select('*')
    .eq('is_active', true)
    .order('room_number', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });

  res.json(residents);
});

// ENDPOINT 3: Dodanie nowego przekazania zmiany
app.post('/api/v1/handover', authenticateToken, async (req, res) => {
  const { resident_id, shift_type, category, note_content } = req.body;

  if (!resident_id || !shift_type || !category || !note_content) {
    return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
  }

  const { data, error } = await supabase
    .from('handover_logs')
    .insert([
      {
        resident_id,
        staff_id: req.user.id,
        shift_type,
        category,
        note_content
      }
    ])
    .select();

  if (error) return res.status(500).json({ error: error.message });

  res.status(201).json({ message: 'Wpis został pomyślnie dodany', log: data[0] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});
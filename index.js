require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { z } = require('zod');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

const app = express();
// Auth is a header key (no cookies), so CORS is not the security boundary.
app.use(
  cors({
    origin: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Organization-Key', 'Idempotency-Key', 'X-Payload-SHA256'],
  })
);
app.use(express.json({ limit: '25mb' }));

/* ---------- helpers identical to the app (sync-protocol.ts) ---------- */

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}
const sha256 = (value) =>
  crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const isoInstant = z.string().datetime({ offset: true });
const shiftKey = z.enum(['morning', 'midday', 'tea', 'night']);
const room = z
  .union([z.string().min(1).max(20), z.number()])
  .transform((v) => `${v}`.trim());

const noteSchema = z.object({
  id: z.string().min(3).max(200),
  type: z.literal('note'),
  date: isoDate,
  windowStart: isoInstant,
  windowEnd: isoInstant,
  room: z.string().min(1).max(20),
  shift: shiftKey,
  text: z.string().max(100000),
  updatedAt: isoInstant,
  deviceId: z.string().min(1).max(100),
  checksum: z.string().regex(/^[0-9a-f]{64}$/),
});

const residentSchema = z.object({
  room,
  name: z.string().max(200),
  tags: z.array(z.string().max(80)).max(50),
  photo: z.string().max(4000000).optional(),
});

const historySchema = z.object({
  id: z.string().min(3).max(300),
  type: z.enum(['admitted', 'released']),
  room,
  name: z.string().max(200),
  tags: z.array(z.string().max(80)).max(50),
  photo: z.string().max(4000000).optional(),
  occurredAtUtc: isoInstant,
  localTime: z.string().max(40),
  utcOffsetMinutes: z.number().int().min(-900).max(900),
  utcOffsetLabel: z.string().max(10),
  dst: z.boolean(),
  timeZone: z.string().max(80),
  operationalDate: isoDate,
  shift: shiftKey,
  sequence: z.number().int().nonnegative(),
});

function split(schema, items) {
  const valid = [];
  let rejected = 0;
  for (const item of Array.isArray(items) ? items : []) {
    const r = schema.safeParse(item);
    if (r.success) valid.push(r.data);
    else rejected += 1;
  }
  return { valid, rejected };
}

function chunks(list, size) {
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  });

/* ---------- organization key check ---------- */

const hashKey = (key) => crypto.createHash('sha256').update(key, 'utf8').digest('hex');

async function findOrCreateOrg(key) {
  const keyHash = hashKey(key);
  const lookup = () =>
    supabase.from('organizations').select('id').eq('key_hash', keyHash).maybeSingle();

  const { data: found } = await lookup();
  if (found) return found;

  // TEST MODE ONLY: the first use of a new key registers it.
  if (process.env.ALLOW_AUTO_REGISTER !== 'true' || key.length < 8) return null;
  const { data: created, error } = await supabase
    .from('organizations')
    .insert({ key_hash: keyHash })
    .select('id')
    .single();
  if (created) return created;
  if (error) {
    const { data: again } = await lookup(); // lost a race with another device
    return again || null;
  }
  return null;
}

async function requireOrg(req, res, next) {
  try {
    const key = String(req.get('X-Organization-Key') || '').trim();
    if (!key) return res.status(401).json({ error: 'Missing organization key' });
    const org = await findOrCreateOrg(key);
    if (!org) return res.status(403).json({ error: 'Unknown organization key' });
    req.orgId = org.id;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

/* ---------- routes ---------- */

// No auth: handy for waking the free Render instance and for a quick browser test.
app.get('/health', (req, res) => res.json({ ok: true }));

// Push notes + residents
app.post(
  '/handover/records',
  requireOrg,
  wrap(async (req, res) => {
    const notes = split(noteSchema, req.body.records);
    const residents = split(residentSchema, req.body.residents);

    // A tampered or stripped record must not be stored.
    const verified = notes.valid.filter((r) => {
      const { checksum, ...body } = r;
      return sha256(body) === checksum;
    });
    const rejected =
      notes.rejected + (notes.valid.length - verified.length) + residents.rejected;

    // Last-write-wins: only store versions newer than what the server already has.
    let stored = 0;
    for (const part of chunks(verified, 100)) {
      const { data: existing, error: e1 } = await supabase
        .from('handover_notes')
        .select('id, updated_at')
        .eq('org_id', req.orgId)
        .in('id', part.map((r) => r.id));
      if (e1) throw e1;
      const have = new Map((existing || []).map((r) => [r.id, new Date(r.updated_at).getTime()]));
      const rows = part
        .filter((r) => !have.has(r.id) || new Date(r.updatedAt).getTime() > have.get(r.id))
        .map((r) => ({
          org_id: req.orgId,
          id: r.id,
          date: r.date,
          room: r.room,
          shift: r.shift,
          text: r.text,
          updated_at: r.updatedAt,
          window_start: r.windowStart,
          window_end: r.windowEnd,
          device_id: r.deviceId,
          checksum: r.checksum,
        }));
      if (rows.length > 0) {
        const { error } = await supabase
          .from('handover_notes')
          .upsert(rows, { onConflict: 'org_id,id' });
        if (error) throw error;
        stored += rows.length;
      }
    }

    for (const part of chunks(residents.valid, 50)) {
      const rows = part.map((r) => ({
        org_id: req.orgId,
        room: r.room,
        name: r.name,
        tags: r.tags,
        photo: r.photo ?? null,
        updated_at: new Date().toISOString(),
      }));
      const { error } = await supabase
        .from('handover_residents')
        .upsert(rows, { onConflict: 'org_id,room' });
      if (error) throw error;
    }

    // The app treats HTTP 200 as "safely stored". If anything was refused,
    // answer 422 so the app keeps the data and does not mark it as synced.
    if (rejected > 0) {
      return res.status(422).json({ ok: false, stored, rejected });
    }
    res.json({ ok: true, stored });
  })
);

// Push room history (admissions / releases)
app.post(
  '/handover/history',
  requireOrg,
  wrap(async (req, res) => {
    const events = split(historySchema, req.body.events);
    for (const part of chunks(events.valid, 100)) {
      const rows = part.map((e) => ({
        org_id: req.orgId,
        id: e.id,
        event: e,
        occurred_at: e.occurredAtUtc,
        operational_date: e.operationalDate,
      }));
      const { error } = await supabase
        .from('handover_history')
        .upsert(rows, { onConflict: 'org_id,id', ignoreDuplicates: true });
      if (error) throw error;
    }
    if (events.rejected > 0) {
      return res.status(422).json({ ok: false, rejected: events.rejected });
    }
    res.json({ ok: true, stored: events.valid.length });
  })
);

// Pull the current operational day (+ residents)
app.get(
  '/handover/records',
  requireOrg,
  wrap(async (req, res) => {
    const date = String(req.query.date || '');
    if (!isoDate.safeParse(date).success) return res.status(400).json({ error: 'Bad date' });

    const { data: notes, error: e1 } = await supabase
      .from('handover_notes')
      .select('*')
      .eq('org_id', req.orgId)
      .eq('date', date);
    if (e1) throw e1;

    const { data: residents, error: e2 } = await supabase
      .from('handover_residents')
      .select('room, name, tags, photo')
      .eq('org_id', req.orgId);
    if (e2) throw e2;

    // serverUpdatedAt is deliberately left out: the app then compares the
    // client's own updatedAt, so a fresh local edit can never be overwritten.
    res.json({
      records: (notes || []).map((n) => ({
        id: n.id,
        type: 'note',
        date: n.date,
        windowStart: new Date(n.window_start).toISOString(),
        windowEnd: new Date(n.window_end).toISOString(),
        room: n.room,
        shift: n.shift,
        text: n.text,
        updatedAt: new Date(n.updated_at).toISOString(),
        deviceId: n.device_id,
        checksum: n.checksum,
      })),
      residents: (residents || []).map((r) => ({
        room: r.room,
        name: r.name,
        tags: r.tags || [],
        ...(r.photo ? { photo: r.photo } : {}),
      })),
    });
  })
);

// Search a past day (used by the boss's history search)
app.get(
  '/handover/search',
  requireOrg,
  wrap(async (req, res) => {
    const date = String(req.query.date || '');
    if (!isoDate.safeParse(date).success) return res.status(400).json({ error: 'Bad date' });

    let query = supabase
      .from('handover_notes')
      .select('id, date, room, shift, text, updated_at')
      .eq('org_id', req.orgId)
      .eq('date', date);

    if (req.query.shift) {
      const shift = shiftKey.safeParse(String(req.query.shift));
      if (!shift.success) return res.status(400).json({ error: 'Bad shift' });
      query = query.eq('shift', shift.data);
    }
    const q = String(req.query.q || '').replace(/[,()%*\\]/g, ' ').trim();
    if (q) query = query.or(`text.ilike.%${q}%,room.ilike.%${q}%`);

    const { data, error } = await query;
    if (error) throw error;
    res.json({
      records: (data || []).map((n) => ({
        id: n.id,
        date: n.date,
        room: n.room,
        shift: n.shift,
        text: n.text,
        updatedAt: new Date(n.updated_at).toISOString(),
      })),
    });
  })
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));

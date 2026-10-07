require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { z } = require('zod');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

// Startup self-check, written to the private Render log. It never prints a key.
function keyKind(key) {
  if (!key) return 'MISSING';
  if (key.startsWith('sb_secret_')) return 'secret key (new format): OK';
  if (key.startsWith('sb_publishable_')) return 'PUBLISHABLE key: WRONG, the backend needs the secret key';
  if (key.startsWith('eyJ')) {
    try {
      const role = JSON.parse(Buffer.from(key.split('.')[1], 'base64url').toString('utf8')).role;
      return role === 'service_role' ? 'legacy service_role key: OK' : `legacy key with role "${role}": WRONG`;
    } catch {
      return 'unreadable legacy key';
    }
  }
  return 'unknown format';
}
(async () => {
  console.log(`[startup] Supabase key: ${keyKind(process.env.SUPABASE_SERVICE_ROLE_KEY)}`);
  const { count, error } = await supabase.from('organizations').select('id', { count: 'exact', head: true });
  console.log(
    error
      ? `[startup] database check FAILED: ${error.message}`
      : `[startup] database check OK, organizations visible: ${count} (expected at least 1)`
  );
})().catch((e) => console.error('[startup] self-check crashed:', e.message));

// Set REQUIRE_MFA=true on Render once the manager has enrolled an authenticator app.
const REQUIRE_MFA = process.env.REQUIRE_MFA === 'true';

const PERMISSIONS = [
  'org.manage',
  'roles.manage',
  'members.view',
  'members.manage',
  'members.reset_pin',
  'devices.manage',
  'audit.read',
  'notes.write',
  'notes.void',
  'notes.approve',
  'residents.manage',
];

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy: needed for the real client IP
app.disable('x-powered-by');
app.use(
  cors({
    origin: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
app.use(express.json({ limit: '25mb' }));

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const newToken = (prefix) => prefix + crypto.randomBytes(32).toString('base64url');
const nowIso = () => new Date().toISOString();

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}
const sha256 = (value) => sha256hex(canonicalize(value));

function chunks(list, size) {
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

// In-memory attempt limiter (single Render instance). Pairing codes have ~40 bits of
// entropy and live 15 minutes, so per-IP and global limits make guessing infeasible.
const attempts = new Map();
function allow(key, max, windowMs) {
  const now = Date.now();
  const list = (attempts.get(key) || []).filter((t) => now - t < windowMs);
  if (list.length >= max) {
    attempts.set(key, list);
    return false;
  }
  list.push(now);
  attempts.set(key, list);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, list] of attempts) {
    const fresh = list.filter((t) => now - t < 3_600_000);
    if (fresh.length) attempts.set(k, fresh);
    else attempts.delete(k);
  }
}, 600_000).unref();

async function audit(orgId, actorType, actorId, action, detail = {}, extra = {}) {
  try {
    await supabase.from('audit_log').insert({
      org_id: orgId || null,
      actor_type: actorType,
      actor_id: actorId ? String(actorId) : null,
      device_id: extra.deviceId || null,
      action,
      detail,
      ip: extra.ip || null,
      occurred_at: extra.occurredAt || null,
      client_event_id: extra.clientEventId || null,
    });
  } catch (err) {
    console.error('audit failed', err);
  }
}

const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  });

const bad = (res, msg = 'Bad request') => res.status(400).json({ error: msg });
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const uuid = z.string().uuid();
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const isoInstant = z.string().datetime({ offset: true });
const shiftKey = z.enum(['morning', 'midday', 'tea', 'night']);
const room = z
  .union([z.string().min(1).max(20), z.number()])
  .transform((v) => `${v}`.trim());

// PIN verifier computed on the tablet (PBKDF2). The server never sees a PIN.
const verifierSchema = z.object({
  salt: z.string().regex(/^[0-9a-f]{32}$/),
  hash: hex64,
  iterations: z.number().int().min(100000).max(2000000),
});

// Least privilege: nobody can grant, edit or reset anything above their own level.
const canGrant = (actorPerms, targetPerms) => targetPerms.every((p) => actorPerms.includes(p));

/* ================================================================== */
/* Wire schemas                                                        */
/* ================================================================== */

const entrySchema = z.object({
  id: z.string().min(3).max(300),
  date: isoDate,
  room: z.string().min(1).max(20),
  shift: shiftKey,
  text: z.string().min(1).max(100000),
  authorId: uuid,
  authorName: z.string().min(1).max(120),
  authorRole: z.string().max(80),
  createdAt: isoInstant,
  checksum: hex64,
});

const voidSchema = z.object({
  id: z.string().min(3).max(300),
  entryId: z.string().min(3).max(300),
  voidedBy: uuid,
  reason: z.string().min(1).max(500),
  createdAt: isoInstant,
  checksum: hex64,
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

const eventSchema = z.object({
  id: z.string().min(1).max(100),
  type: z.string().regex(/^[a-z_.]{3,60}$/),
  memberId: uuid.optional(),
  at: isoInstant,
  detail: z.record(z.any()).optional(),
});

// Validates items one by one. A single bad item must never block the others.
function validateItems(schema, items) {
  const valid = [];
  const rejected = [];
  for (const item of Array.isArray(items) ? items : []) {
    const r = schema.safeParse(item);
    if (r.success) valid.push(r.data);
    else rejected.push({ id: String(item?.id ?? ''), reason: 'INVALID' });
  }
  return { valid, rejected };
}

/* ================================================================== */
/* Authentication                                                      */
/* ================================================================== */

function bearerOf(req) {
  const m = /^Bearer (.+)$/i.exec(req.get('Authorization') || '');
  return m ? m[1].trim() : '';
}

/* ---------- tablets: device token ---------- */

async function requireDevice(req, res, next) {
  try {
    const token = bearerOf(req);
    if (!token.startsWith('dev_'))
      return res.status(401).json({ error: 'Missing device token', code: 'NO_TOKEN' });
    const { data: device } = await supabase
      .from('devices')
      .select('id, org_id, revoked_at, last_seen_at')
      .eq('token_hash', sha256hex(token))
      .maybeSingle();
    if (!device) return res.status(401).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    if (device.revoked_at)
      return res.status(401).json({ error: 'Device revoked', code: 'DEVICE_REVOKED' });
    const last = device.last_seen_at ? new Date(device.last_seen_at).getTime() : 0;
    if (Date.now() - last > 60_000) {
      supabase.from('devices').update({ last_seen_at: nowIso() }).eq('id', device.id).then(() => {});
    }
    req.orgId = device.org_id;
    req.deviceId = device.id;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

/* ---------- managers / deputies: Supabase Auth (email, password, MFA) ---------- */

const MEMBER_COLS =
  'id, org_id, auth_user_id, email, full_name, active, archived_at, pin_algo, pin_iterations, pin_salt, pin_hash, pin_version, must_change_pin, updated_at, role:roles(id, key, name, permissions)';

function jwtAal(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).aal || null;
  } catch {
    return null;
  }
}

async function loadAdmin(req) {
  const token = bearerOf(req);
  if (!token || token.startsWith('dev_')) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    console.error('[auth] token check failed:', error?.message || 'no user returned');
    return null;
  }
  const user = data.user;

  const first = await supabase
    .from('members')
    .select(MEMBER_COLS)
    .eq('auth_user_id', user.id)
    .maybeSingle();
  if (first.error) console.error('[auth] member lookup error:', first.error.message);
  let member = first.data;

  // First login: link the Auth account to the member with the same VERIFIED email.
  if (!member && user.email && user.email_confirmed_at) {
    const { data: byEmail, error: emailErr } = await supabase
      .from('members')
      .select('id')
      .eq('email', user.email.toLowerCase())
      .is('auth_user_id', null)
      .maybeSingle();
    if (emailErr) console.error('[auth] lookup by email error:', emailErr.message);
    if (!byEmail) console.error('[auth] no unlinked member found for the signed-in email');
    if (byEmail) {
      const upd = await supabase.from('members').update({ auth_user_id: user.id }).eq('id', byEmail.id).is('auth_user_id', null);
      if (upd.error) console.error('[auth] linking failed:', upd.error.message);
      const linked = await supabase.from('members').select(MEMBER_COLS).eq('id', byEmail.id).maybeSingle();
      if (linked.error) console.error('[auth] reading linked member failed:', linked.error.message);
      member = linked.data;
      if (member) await audit(member.org_id, 'member', member.id, 'member.login_linked', { email: user.email });
    }
  }
  if (!member || !member.active || member.archived_at) {
    console.error('[auth] sign-in refused: no active member for this account');
    return null;
  }
  return {
    id: member.id,
    orgId: member.org_id,
    name: member.full_name,
    roleKey: member.role.key,
    permissions: member.role.permissions,
    aal: jwtAal(token),
  };
}

// Usage: need('members.manage'). With no arguments: any signed-in member.
const need =
  (...perms) =>
  async (req, res, next) => {
    try {
      const admin = await loadAdmin(req);
      if (!admin) return res.status(401).json({ error: 'Sign-in required', code: 'NO_ADMIN' });
      if (REQUIRE_MFA && admin.aal !== 'aal2')
        return res.status(403).json({ error: 'Second factor required', code: 'MFA_REQUIRED' });
      if (perms.some((p) => !admin.permissions.includes(p)))
        return res.status(403).json({ error: 'Not allowed', code: 'FORBIDDEN' });
      req.admin = admin;
      req.orgId = admin.orgId;
      next();
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  };

/* ================================================================== */
/* Views                                                               */
/* ================================================================== */

const memberForAdmin = (m) => ({
  id: m.id,
  fullName: m.full_name,
  email: m.email,
  roleKey: m.role.key,
  roleName: m.role.name,
  permissions: m.role.permissions,
  active: m.active && !m.archived_at,
  archived: Boolean(m.archived_at),
  hasPin: Boolean(m.pin_hash),
  mustChangePin: m.must_change_pin,
  pinVersion: m.pin_version,
  hasLogin: Boolean(m.auth_user_id),
  updatedAt: m.updated_at,
});

// Tablets receive the verifier so they can check PINs offline.
const memberForDevice = (m) => ({
  id: m.id,
  fullName: m.full_name,
  roleKey: m.role.key,
  roleName: m.role.name,
  permissions: m.role.permissions,
  active: m.active && !m.archived_at,
  archived: Boolean(m.archived_at),
  mustChangePin: m.must_change_pin,
  pinVersion: m.pin_version,
  pin: m.pin_hash
    ? { algo: m.pin_algo, salt: m.pin_salt, hash: m.pin_hash, iterations: m.pin_iterations }
    : null,
  updatedAt: m.updated_at,
});

async function orgPolicy(orgId) {
  const { data } = await supabase
    .from('organizations')
    .select('name, max_offline_days, idle_logout_minutes, pin_salt, pin_iterations')
    .eq('id', orgId)
    .single();
  return {
    organizationName: data?.name || '',
    maxOfflineDays: data?.max_offline_days ?? 14,
    idleLogoutMinutes: data?.idle_logout_minutes ?? 15,
    pinSalt: data?.pin_salt || '',
    pinIterations: data?.pin_iterations ?? 310000,
  };
}

// PINs are identified by a "tag" prepared with the care home's own salt, so the same PIN
// always gives the same tag. A PIN prepared with other settings cannot be compared.
async function pinSettingsOk(orgId, pin) {
  const { data } = await supabase
    .from('organizations')
    .select('pin_salt, pin_iterations')
    .eq('id', orgId)
    .single();
  return Boolean(data) && pin.salt === data.pin_salt && pin.iterations === data.pin_iterations;
}

const PIN_SETTINGS_BODY = {
  error: 'This PIN was prepared with old settings. Refresh the page and try again.',
  code: 'PIN_SETTINGS_CHANGED',
};
const PIN_TAKEN_BODY = {
  error: 'That PIN is already used by someone else. Choose another.',
  code: 'PIN_TAKEN',
};
// The database refuses a second person with the same PIN (unique index members_pin_unique).
const isPinTaken = (error) =>
  Boolean(error) && error.code === '23505' && /members_pin_unique/.test(`${error.message} ${error.details || ''}`);

async function loadMembers(orgId) {
  const { data, error } = await supabase
    .from('members')
    .select(MEMBER_COLS)
    .eq('org_id', orgId)
    .order('full_name');
  if (error) throw error;
  return data || [];
}

async function isLastManager(orgId, memberId) {
  const members = await loadMembers(orgId);
  const managers = members.filter(
    (m) => m.active && !m.archived_at && m.role.permissions.includes('org.manage')
  );
  return managers.length === 1 && managers[0].id === memberId;
}

/* ================================================================== */
/* Public                                                              */
/* ================================================================== */

// No auth: wakes the free Render instance.
app.get('/health', (req, res) => res.json({ ok: true }));

/* ================================================================== */
/* Device pairing (needs internet, once per tablet)                    */
/* ================================================================== */

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
function newPairingCode() {
  let out = '';
  for (let i = 0; i < 8; i += 1) out += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  return out;
}
const normalizeCode = (s) => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

app.post(
  '/devices/pair',
  wrap(async (req, res) => {
    if (!allow(`pair:${req.ip}`, 10, 10 * 60_000) || !allow('pair:global', 60, 10 * 60_000))
      return res.status(429).json({ error: 'Too many attempts. Try again later.' });

    const body = z
      .object({
        code: z.string().min(6).max(20),
        deviceName: z.string().trim().max(80).optional(),
        clientDeviceId: z.string().max(100).optional(),
      })
      .safeParse(req.body);
    if (!body.success) return bad(res);
    const code = normalizeCode(body.data.code);
    if (code.length !== 8) return bad(res, 'Invalid code');

    // Atomic consume: two tablets can never use the same code.
    const { data: consumed, error: cErr } = await supabase
      .from('pairing_codes')
      .update({ used_at: nowIso() })
      .eq('code_hash', sha256hex(code))
      .is('used_at', null)
      .gt('expires_at', nowIso())
      .select('id, org_id, device_name, created_by')
      .maybeSingle();
    if (cErr) throw cErr;
    if (!consumed) return bad(res, 'Code is invalid, expired or already used');

    const token = newToken('dev_');
    const { data: device, error: dErr } = await supabase
      .from('devices')
      .insert({
        org_id: consumed.org_id,
        name: body.data.deviceName || consumed.device_name || '',
        token_hash: sha256hex(token),
        client_device_id: body.data.clientDeviceId || null,
        paired_by: consumed.created_by,
        last_seen_at: nowIso(),
      })
      .select('id')
      .single();
    if (dErr) throw dErr;
    await supabase.from('pairing_codes').update({ used_by_device: device.id }).eq('id', consumed.id);

    const members = await loadMembers(consumed.org_id);
    await audit(consumed.org_id, 'device', device.id, 'device.paired', {}, { ip: req.ip, deviceId: device.id });
    res.json({
      token,
      deviceId: device.id,
      members: members.map(memberForDevice),
      policy: await orgPolicy(consumed.org_id),
      serverTime: nowIso(),
    });
  })
);

/* ================================================================== */
/* Tablet sync (all idempotent; the tablet works fully offline)        */
/* ================================================================== */

// Staff list with PIN verifiers + org policy. Also the "is this device still valid" check.
app.get(
  '/sync/members',
  requireDevice,
  wrap(async (req, res) => {
    const members = await loadMembers(req.orgId);
    res.json({
      members: members.map(memberForDevice),
      policy: await orgPolicy(req.orgId),
      serverTime: nowIso(),
    });
  })
);

// PIN changes queued on the tablet.
//  - self change:      { pin, basedOnVersion }                   -> must_change_pin = false
//  - on-site reset:    { pin, basedOnVersion, approvedBy }       -> must_change_pin = true
// The server cannot see who is at the keyboard, so every change is audited with the device.
app.post(
  '/sync/members/:id/pin',
  requireDevice,
  wrap(async (req, res) => {
    if (!uuid.safeParse(req.params.id).success) return bad(res);
    const body = z
      .object({
        pin: verifierSchema,
        basedOnVersion: z.number().int().min(0),
        approvedBy: uuid.optional(),
      })
      .safeParse(req.body);
    if (!body.success) return bad(res);

    const { data: target } = await supabase
      .from('members')
      .select(MEMBER_COLS)
      .eq('id', req.params.id)
      .eq('org_id', req.orgId)
      .maybeSingle();
    if (!target || target.archived_at) return res.status(404).json({ error: 'Member not found' });

    // Same change sent again (the reply was lost): success.
    if (target.pin_salt === body.data.pin.salt && target.pin_hash === body.data.pin.hash)
      return res.json({ ok: true, member: memberForDevice(target) });

    // An administrator reset the PIN meanwhile: the reset wins.
    if (target.pin_version !== body.data.basedOnVersion)
      return res
        .status(409)
        .json({ error: 'PIN was changed meanwhile', code: 'PIN_CONFLICT', member: memberForDevice(target) });

    // A PIN prepared with other settings than the care home's current ones cannot be compared.
    if (!(await pinSettingsOk(req.orgId, body.data.pin))) return res.status(400).json(PIN_SETTINGS_BODY);

    let mustChange = false;
    if (body.data.approvedBy) {
      const { data: approver } = await supabase
        .from('members')
        .select(MEMBER_COLS)
        .eq('id', body.data.approvedBy)
        .eq('org_id', req.orgId)
        .maybeSingle();
      const ok =
        approver &&
        approver.active &&
        !approver.archived_at &&
        approver.role.permissions.includes('members.reset_pin') &&
        canGrant(approver.role.permissions, target.role.permissions);
      if (!ok) return res.status(403).json({ error: 'Approver not allowed', code: 'FORBIDDEN' });
      mustChange = true;
    } else if (!target.active) {
      return res.status(403).json({ error: 'Member is deactivated', code: 'FORBIDDEN' });
    }

    const { data: updated, error } = await supabase
      .from('members')
      .update({
        pin_algo: 'pbkdf2-sha256',
        pin_iterations: body.data.pin.iterations,
        pin_salt: body.data.pin.salt,
        pin_hash: body.data.pin.hash,
        pin_version: target.pin_version + 1,
        must_change_pin: mustChange,
        updated_at: nowIso(),
      })
      .eq('id', target.id)
      .eq('org_id', req.orgId)
      .eq('pin_version', target.pin_version) // optimistic lock
      .select(MEMBER_COLS)
      .maybeSingle();
    if (isPinTaken(error)) {
      // Someone else (on another device) already holds this PIN: this person must choose again.
      await audit(req.orgId, 'device', req.deviceId, 'member.pin_rejected_taken', { memberId: target.id }, { ip: req.ip, deviceId: req.deviceId });
      return res.status(409).json({ ...PIN_TAKEN_BODY, member: memberForDevice(target) });
    }
    if (error) throw error;
    if (!updated) {
      const fresh = await supabase.from('members').select(MEMBER_COLS).eq('id', target.id).single();
      return res
        .status(409)
        .json({ error: 'PIN was changed meanwhile', code: 'PIN_CONFLICT', member: memberForDevice(fresh.data) });
    }
    await audit(
      req.orgId,
      'device',
      req.deviceId,
      body.data.approvedBy ? 'member.pin_reset_on_site' : 'member.pin_changed',
      { memberId: target.id, approvedBy: body.data.approvedBy || null },
      { ip: req.ip, deviceId: req.deviceId }
    );
    res.json({ ok: true, member: memberForDevice(updated) });
  })
);

// Care note entries + voids. Per-item results: one bad item never blocks the rest.
app.post(
  '/sync/entries',
  requireDevice,
  wrap(async (req, res) => {
    const entries = validateItems(entrySchema, req.body.entries);
    const voids = validateItems(voidSchema, req.body.voids);
    const rejected = [...entries.rejected, ...voids.rejected];
    const acceptedIds = [];

    // Integrity: a tampered or stripped record is refused.
    const signedEntries = entries.valid.filter((e) => {
      const { checksum, ...body } = e;
      if (sha256(body) === checksum) return true;
      rejected.push({ id: e.id, reason: 'BAD_CHECKSUM' });
      return false;
    });
    const signedVoids = voids.valid.filter((v) => {
      const { checksum, ...body } = v;
      if (sha256(body) === checksum) return true;
      rejected.push({ id: v.id, reason: 'BAD_CHECKSUM' });
      return false;
    });

    // Authors must be members of THIS organization (archived ones are fine: their
    // offline entries written before they left must still be accepted).
    const memberIds = [...new Set([...signedEntries.map((e) => e.authorId), ...signedVoids.map((v) => v.voidedBy)])];
    const known = new Map();
    for (const part of chunks(memberIds, 200)) {
      const { data, error } = await supabase
        .from('members')
        .select('id, role:roles(permissions)')
        .eq('org_id', req.orgId)
        .in('id', part);
      if (error) throw error;
      for (const m of data || []) known.set(m.id, m.role.permissions);
    }

    const okEntries = signedEntries.filter((e) => {
      if (known.has(e.authorId)) return true;
      rejected.push({ id: e.id, reason: 'UNKNOWN_AUTHOR' });
      return false;
    });
    for (const part of chunks(okEntries, 100)) {
      const rows = part.map((e) => ({
        org_id: req.orgId,
        id: e.id,
        operational_date: e.date,
        room: e.room,
        shift: e.shift,
        text: e.text,
        author_member_id: e.authorId,
        author_name: e.authorName,
        author_role: e.authorRole,
        created_at_device: e.createdAt,
        device_id: req.deviceId, // taken from the token, never from the client
        checksum: e.checksum,
      }));
      const { error } = await supabase
        .from('note_entries')
        .upsert(rows, { onConflict: 'org_id,id', ignoreDuplicates: true });
      if (error) throw error;
      acceptedIds.push(...part.map((e) => e.id));
    }

    // Voids: the entry must exist; only its author or a holder of notes.void may void it.
    const entryIds = [...new Set(signedVoids.map((v) => v.entryId))];
    const authorOf = new Map();
    for (const part of chunks(entryIds, 200)) {
      const { data, error } = await supabase
        .from('note_entries')
        .select('id, author_member_id')
        .eq('org_id', req.orgId)
        .in('id', part);
      if (error) throw error;
      for (const e of data || []) authorOf.set(e.id, e.author_member_id);
    }
    const okVoids = signedVoids.filter((v) => {
      if (!authorOf.has(v.entryId)) {
        rejected.push({ id: v.id, reason: 'UNKNOWN_ENTRY' }); // retry after the entry syncs
        return false;
      }
      const perms = known.get(v.voidedBy);
      const allowed =
        perms && (authorOf.get(v.entryId) === v.voidedBy || perms.includes('notes.void'));
      if (!allowed) {
        rejected.push({ id: v.id, reason: 'NOT_ALLOWED' });
        return false;
      }
      return true;
    });
    for (const part of chunks(okVoids, 100)) {
      const rows = part.map((v) => ({
        org_id: req.orgId,
        id: v.id,
        entry_id: v.entryId,
        voided_by: v.voidedBy,
        reason: v.reason,
        created_at_device: v.createdAt,
        device_id: req.deviceId,
        checksum: v.checksum,
      }));
      const { error } = await supabase
        .from('note_entry_voids')
        .upsert(rows, { onConflict: 'org_id,id', ignoreDuplicates: true });
      if (error) throw error;
      acceptedIds.push(...part.map((v) => v.id));
    }

    res.json({ acceptedIds, rejected });
  })
);

app.post(
  '/sync/residents',
  requireDevice,
  wrap(async (req, res) => {
    const residents = validateItems(residentSchema, req.body.residents);
    for (const part of chunks(residents.valid, 50)) {
      const rows = part.map((r) => ({
        org_id: req.orgId,
        room: r.room,
        name: r.name,
        tags: r.tags,
        photo: r.photo ?? null,
        updated_at: nowIso(),
      }));
      const { error } = await supabase
        .from('handover_residents')
        .upsert(rows, { onConflict: 'org_id,room' });
      if (error) throw error;
    }
    res.json({ ok: true, stored: residents.valid.length, rejected: residents.rejected });
  })
);

app.post(
  '/sync/history',
  requireDevice,
  wrap(async (req, res) => {
    const events = validateItems(historySchema, req.body.events);
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
    res.json({ acceptedIds: events.valid.map((e) => e.id), rejected: events.rejected });
  })
);

// Security events recorded offline on the tablet (logins, failed PINs, logouts...).
app.post(
  '/sync/events',
  requireDevice,
  wrap(async (req, res) => {
    const events = validateItems(eventSchema, (req.body.events || []).slice(0, 500));
    for (const part of chunks(events.valid, 100)) {
      const rows = part.map((e) => ({
        org_id: req.orgId,
        occurred_at: e.at,
        actor_type: 'device',
        actor_id: e.memberId || null,
        device_id: req.deviceId,
        action: `device.${e.type}`,
        detail: e.detail || {},
        ip: req.ip,
        client_event_id: e.id,
      }));
      const { error } = await supabase
        .from('audit_log')
        .upsert(rows, { onConflict: 'org_id,device_id,client_event_id', ignoreDuplicates: true });
      if (error) throw error;
    }
    res.json({ acceptedIds: events.valid.map((e) => e.id), rejected: events.rejected });
  })
);

const mapEntry = (n) => ({
  id: n.id,
  date: n.operational_date,
  room: n.room,
  shift: n.shift,
  text: n.text,
  authorId: n.author_member_id,
  authorName: n.author_name,
  authorRole: n.author_role,
  createdAt: new Date(n.created_at_device).toISOString(),
  receivedAt: new Date(n.received_at).toISOString(),
  checksum: n.checksum,
});

async function loadVoids(orgId, entryIds) {
  const out = [];
  for (const part of chunks(entryIds, 200)) {
    const { data, error } = await supabase
      .from('note_entry_voids')
      .select('id, entry_id, voided_by, reason, created_at_device, received_at, checksum')
      .eq('org_id', orgId)
      .in('entry_id', part);
    if (error) throw error;
    for (const v of data || [])
      out.push({
        id: v.id,
        entryId: v.entry_id,
        voidedBy: v.voided_by,
        reason: v.reason,
        createdAt: new Date(v.created_at_device).toISOString(),
        receivedAt: new Date(v.received_at).toISOString(),
        checksum: v.checksum,
      });
  }
  return out;
}

// Pull the current operational day (+ residents).
app.get(
  '/sync/day',
  requireDevice,
  wrap(async (req, res) => {
    const date = String(req.query.date || '');
    if (!isoDate.safeParse(date).success) return bad(res, 'Bad date');
    const { data: entries, error: e1 } = await supabase
      .from('note_entries')
      .select('*')
      .eq('org_id', req.orgId)
      .eq('operational_date', date)
      .order('created_at_device');
    if (e1) throw e1;
    const { data: residents, error: e2 } = await supabase
      .from('handover_residents')
      .select('room, name, tags, photo')
      .eq('org_id', req.orgId);
    if (e2) throw e2;
    res.json({
      entries: (entries || []).map(mapEntry),
      voids: await loadVoids(req.orgId, (entries || []).map((e) => e.id)),
      residents: (residents || []).map((r) => ({
        room: r.room,
        name: r.name,
        tags: r.tags || [],
        ...(r.photo ? { photo: r.photo } : {}),
      })),
    });
  })
);

// Search a past day (history is never cached on the tablet).
app.get(
  '/sync/search',
  requireDevice,
  wrap(async (req, res) => {
    const date = String(req.query.date || '');
    if (!isoDate.safeParse(date).success) return bad(res, 'Bad date');
    let query = supabase
      .from('note_entries')
      .select('*')
      .eq('org_id', req.orgId)
      .eq('operational_date', date)
      .order('created_at_device');
    if (req.query.shift) {
      const shift = shiftKey.safeParse(String(req.query.shift));
      if (!shift.success) return bad(res, 'Bad shift');
      query = query.eq('shift', shift.data);
    }
    const q = String(req.query.q || '').replace(/[,()%*\\]/g, ' ').trim();
    if (q) query = query.or(`text.ilike.%${q}%,room.ilike.%${q}%,author_name.ilike.%${q}%`);
    const { data, error } = await query;
    if (error) throw error;
    const voids = await loadVoids(req.orgId, (data || []).map((e) => e.id));
    const voided = new Set(voids.map((v) => v.entryId));
    res.json({ entries: (data || []).map((n) => ({ ...mapEntry(n), voided: voided.has(n.id) })), voids });
  })
);

/* ================================================================== */
/* Administration (Supabase Auth + permissions)                        */
/* ================================================================== */

app.get(
  '/admin/me',
  need(),
  wrap(async (req, res) => {
    res.json({
      id: req.admin.id,
      name: req.admin.name,
      roleKey: req.admin.roleKey,
      permissions: req.admin.permissions,
      mfa: req.admin.aal === 'aal2',
      pinSalt: (await orgPolicy(req.orgId)).pinSalt,
      pinIterations: (await orgPolicy(req.orgId)).pinIterations,
    });
  })
);

app.get(
  '/admin/org',
  need('org.manage'),
  wrap(async (req, res) => res.json(await orgPolicy(req.orgId)))
);

app.patch(
  '/admin/org',
  need('org.manage'),
  wrap(async (req, res) => {
    const body = z
      .object({
        name: z.string().trim().min(1).max(120).optional(),
        maxOfflineDays: z.number().int().min(1).max(90).optional(),
        idleLogoutMinutes: z.number().int().min(1).max(240).optional(),
      })
      .safeParse(req.body);
    if (!body.success || Object.keys(body.data).length === 0) return bad(res);
    const patch = {};
    if (body.data.name !== undefined) patch.name = body.data.name;
    if (body.data.maxOfflineDays !== undefined) patch.max_offline_days = body.data.maxOfflineDays;
    if (body.data.idleLogoutMinutes !== undefined) patch.idle_logout_minutes = body.data.idleLogoutMinutes;
    const { error } = await supabase.from('organizations').update(patch).eq('id', req.orgId);
    if (error) throw error;
    await audit(req.orgId, 'member', req.admin.id, 'org.updated', body.data, { ip: req.ip });
    res.json(await orgPolicy(req.orgId));
  })
);

app.get(
  '/admin/roles',
  need('members.view'),
  wrap(async (req, res) => {
    const { data, error } = await supabase
      .from('roles')
      .select('id, key, name, permissions, is_system')
      .eq('org_id', req.orgId)
      .order('name');
    if (error) throw error;
    res.json({ roles: data || [], allPermissions: PERMISSIONS });
  })
);

/* ---------- members ---------- */

app.get(
  '/admin/members',
  need('members.view'),
  wrap(async (req, res) => {
    const members = await loadMembers(req.orgId);
    res.json({ members: members.filter((m) => !m.archived_at).map(memberForAdmin) });
  })
);

async function roleByKey(orgId, key) {
  const { data } = await supabase
    .from('roles')
    .select('id, key, name, permissions')
    .eq('org_id', orgId)
    .eq('key', key)
    .maybeSingle();
  return data;
}

app.post(
  '/admin/members',
  need('members.manage'),
  wrap(async (req, res) => {
    const body = z
      .object({
        fullName: z.string().trim().min(1).max(120),
        email: z.string().trim().toLowerCase().email().max(200).optional(),
        roleKey: z.string().min(1).max(40),
        pin: verifierSchema.optional(), // temporary PIN verifier computed in the admin's browser
      })
      .safeParse(req.body);
    if (!body.success) return bad(res);
    const role = await roleByKey(req.orgId, body.data.roleKey);
    if (!role) return res.status(404).json({ error: 'Role not found' });
    if (!canGrant(req.admin.permissions, role.permissions))
      return res.status(403).json({ error: 'You cannot assign a role above your own', code: 'FORBIDDEN' });
    if (body.data.pin && !(await pinSettingsOk(req.orgId, body.data.pin)))
      return res.status(400).json(PIN_SETTINGS_BODY);

    const { data, error } = await supabase
      .from('members')
      .insert({
        org_id: req.orgId,
        full_name: body.data.fullName,
        email: body.data.email || null,
        role_id: role.id,
        ...(body.data.pin
          ? {
              pin_algo: 'pbkdf2-sha256',
              pin_iterations: body.data.pin.iterations,
              pin_salt: body.data.pin.salt,
              pin_hash: body.data.pin.hash,
              pin_version: 1,
            }
          : {}),
        must_change_pin: true,
      })
      .select(MEMBER_COLS)
      .single();
    if (error) {
      if (isPinTaken(error)) return res.status(409).json(PIN_TAKEN_BODY);
      if (error.code === '23505') return res.status(409).json({ error: 'That email is already in use' });
      throw error;
    }
    await audit(req.orgId, 'member', req.admin.id, 'member.created', { memberId: data.id, role: role.key }, { ip: req.ip });
    res.json({ member: memberForAdmin(data) });
  })
);

async function loadTarget(req, res) {
  if (!uuid.safeParse(req.params.id).success) {
    bad(res);
    return null;
  }
  const { data } = await supabase
    .from('members')
    .select(MEMBER_COLS)
    .eq('id', req.params.id)
    .eq('org_id', req.orgId)
    .maybeSingle();
  if (!data || data.archived_at) {
    res.status(404).json({ error: 'Member not found' });
    return null;
  }
  if (!canGrant(req.admin.permissions, data.role.permissions)) {
    res.status(403).json({ error: 'You cannot change a member above your own level', code: 'FORBIDDEN' });
    return null;
  }
  return data;
}

app.patch(
  '/admin/members/:id',
  need('members.manage'),
  wrap(async (req, res) => {
    const body = z
      .object({
        fullName: z.string().trim().min(1).max(120).optional(),
        email: z.string().trim().toLowerCase().email().max(200).nullable().optional(),
        roleKey: z.string().min(1).max(40).optional(),
        active: z.boolean().optional(),
      })
      .safeParse(req.body);
    if (!body.success || Object.keys(body.data).length === 0) return bad(res);
    const target = await loadTarget(req, res);
    if (!target) return;

    const patch = { updated_at: nowIso() };
    if (body.data.fullName !== undefined) patch.full_name = body.data.fullName;
    if (body.data.email !== undefined) patch.email = body.data.email;
    if (body.data.active !== undefined) patch.active = body.data.active;
    let losesManager = body.data.active === false;
    if (body.data.roleKey !== undefined) {
      const role = await roleByKey(req.orgId, body.data.roleKey);
      if (!role) return res.status(404).json({ error: 'Role not found' });
      if (!canGrant(req.admin.permissions, role.permissions))
        return res.status(403).json({ error: 'You cannot assign a role above your own', code: 'FORBIDDEN' });
      patch.role_id = role.id;
      if (!role.permissions.includes('org.manage')) losesManager = true;
    }
    if (losesManager && (await isLastManager(req.orgId, target.id)))
      return res.status(409).json({ error: 'The organization must keep at least one active manager' });

    const { data, error } = await supabase
      .from('members')
      .update(patch)
      .eq('id', target.id)
      .eq('org_id', req.orgId)
      .select(MEMBER_COLS)
      .single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'That email is already in use' });
      throw error;
    }
    await audit(req.orgId, 'member', req.admin.id, 'member.updated', { memberId: target.id, changed: Object.keys(body.data) }, { ip: req.ip });
    res.json({ member: memberForAdmin(data) });
  })
);

// Set or reset a temporary PIN. The version rises, so it beats any offline change.
app.post(
  '/admin/members/:id/pin',
  need('members.reset_pin'),
  wrap(async (req, res) => {
    const body = z.object({ pin: verifierSchema }).safeParse(req.body);
    if (!body.success) return bad(res);
    const target = await loadTarget(req, res);
    if (!target) return;
    if (!(await pinSettingsOk(req.orgId, body.data.pin))) return res.status(400).json(PIN_SETTINGS_BODY);
    const { data, error } = await supabase
      .from('members')
      .update({
        pin_algo: 'pbkdf2-sha256',
        pin_iterations: body.data.pin.iterations,
        pin_salt: body.data.pin.salt,
        pin_hash: body.data.pin.hash,
        pin_version: target.pin_version + 1,
        must_change_pin: true,
        updated_at: nowIso(),
      })
      .eq('id', target.id)
      .eq('org_id', req.orgId)
      .select(MEMBER_COLS)
      .single();
    if (error) {
      if (isPinTaken(error)) return res.status(409).json(PIN_TAKEN_BODY);
      throw error;
    }
    await audit(req.orgId, 'member', req.admin.id, 'member.pin_reset', { memberId: target.id }, { ip: req.ip });
    res.json({ member: memberForAdmin(data) });
  })
);

// Nothing is deleted from care records: leaving staff are archived.
app.delete(
  '/admin/members/:id',
  need('members.manage'),
  wrap(async (req, res) => {
    const target = await loadTarget(req, res);
    if (!target) return;
    if (target.id === req.admin.id)
      return res.status(409).json({ error: 'You cannot archive your own account' });
    if (await isLastManager(req.orgId, target.id))
      return res.status(409).json({ error: 'The organization must keep at least one active manager' });
    const { error } = await supabase
      .from('members')
      .update({
        active: false,
        archived_at: nowIso(),
        updated_at: nowIso(),
        // an archived person can never sign in again: free their PIN for someone else
        pin_algo: null,
        pin_iterations: null,
        pin_salt: null,
        pin_hash: null,
      })
      .eq('id', target.id)
      .eq('org_id', req.orgId);
    if (error) throw error;
    await audit(req.orgId, 'member', req.admin.id, 'member.archived', { memberId: target.id }, { ip: req.ip });
    res.json({ ok: true });
  })
);

/* ---------- devices ---------- */

app.post(
  '/admin/pairing-codes',
  need('devices.manage'),
  wrap(async (req, res) => {
    const body = z.object({ deviceName: z.string().trim().max(80).optional() }).safeParse(req.body);
    if (!body.success) return bad(res);
    const code = newPairingCode();
    const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
    const { error } = await supabase.from('pairing_codes').insert({
      org_id: req.orgId,
      code_hash: sha256hex(code),
      device_name: body.data.deviceName || '',
      created_by: req.admin.id,
      expires_at: expiresAt,
    });
    if (error) throw error;
    await audit(req.orgId, 'member', req.admin.id, 'pairing_code.created', { deviceName: body.data.deviceName || '' }, { ip: req.ip });
    res.json({ code: `${code.slice(0, 4)}-${code.slice(4)}`, expiresAt });
  })
);

app.get(
  '/admin/devices',
  need('devices.manage'),
  wrap(async (req, res) => {
    const { data, error } = await supabase
      .from('devices')
      .select('id, name, created_at, last_seen_at, revoked_at')
      .eq('org_id', req.orgId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({
      devices: (data || []).map((d) => ({
        id: d.id,
        name: d.name,
        pairedAt: d.created_at,
        lastSeenAt: d.last_seen_at,
        revokedAt: d.revoked_at,
      })),
    });
  })
);

// Revoking blocks the tablet from syncing. Unsent notes stay on the tablet.
app.delete(
  '/admin/devices/:id',
  need('devices.manage'),
  wrap(async (req, res) => {
    if (!uuid.safeParse(req.params.id).success) return bad(res);
    const { data, error } = await supabase
      .from('devices')
      .update({ revoked_at: nowIso(), revoked_by: req.admin.id })
      .eq('id', req.params.id)
      .eq('org_id', req.orgId)
      .is('revoked_at', null)
      .select('id')
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Device not found' });
    await audit(req.orgId, 'member', req.admin.id, 'device.revoked', { deviceId: data.id }, { ip: req.ip });
    res.json({ ok: true });
  })
);

/* ---------- audit log ---------- */

app.get(
  '/admin/audit',
  need('audit.read'),
  wrap(async (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    let query = supabase
      .from('audit_log')
      .select('id, received_at, occurred_at, actor_type, actor_id, device_id, action, detail, ip')
      .eq('org_id', req.orgId)
      .order('id', { ascending: false })
      .limit(limit);
    const before = parseInt(req.query.before, 10);
    if (Number.isFinite(before)) query = query.lt('id', before);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ events: data || [] });
  })
);

/* ================================================================== */
/* Errors                                                              */
/* ================================================================== */

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));
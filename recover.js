// RECOVERY COMMAND FOR THE SUPPLIER (I.4, 2026-10-22).
//
// For the rare case when NOBODY with full access can sign in to a care home's panel any more
// (for example: the only manager left suddenly, or lost their phone and password at once).
//
// Rules (written in the Help page too):
//  1. Only on a WRITTEN request from the care home's company (letter or e-mail from the owner /
//     director), never on a phone call alone.
//  2. Check who you are talking to: call back on the number in the CQC register, not on a number
//     given in the request.
//  3. Run first WITHOUT --confirm: it only shows what would happen. Then run again with --confirm.
//  4. Everything is written to the Activity log ("Supplier recovery ...") and, if e-mail is set up
//     here, a warning e-mail goes to everyone with full access. Nothing is ever deleted.
//
// Usage (in the carehandover-backend folder, PowerShell):
//   node recover.js --email manager@example.com --request "Letter from Capel Grange Ltd, 23 Oct 2026, signed J. Smith"
//   node recover.js --email manager@example.com --request "..." --reset-2fa --confirm
//
// Options:
//   --email      the work e-mail of the person who should get full access back (must already be on
//                the staff list, or among past staff)
//   --request    what the written request was (who, when) - kept in the Activity log
//   --reset-2fa  also remove their authenticator app (lost phone)
//   --confirm    really do it (without it: only shows the plan)
//
// It needs SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the .env file next to this file (the same
// values as on Render). Never send these to anyone and never put them in the app.
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const INVITE_REDIRECT_URL = process.env.INVITE_REDIRECT_URL || 'https://handover-app.pages.dev/accept-invite';
const FULL_ROLE_KEY = 'registered_manager';

function args(argv) {
  const out = { resetTwoFactor: false, confirm: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--email') out.email = (argv[++i] || '').trim().toLowerCase();
    else if (a === '--request') out.request = (argv[++i] || '').trim();
    else if (a === '--reset-2fa') out.resetTwoFactor = true;
    else if (a === '--confirm') out.confirm = true;
    else out.unknown = a;
  }
  return out;
}

async function main(argv, say = console.log) {
  const o = args(argv);
  if (o.unknown) return fail(say, `Unknown option: ${o.unknown}`);
  if (!o.email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(o.email)) return fail(say, 'Give the work email: --email someone@example.com');
  if (!o.request || o.request.length < 10)
    return fail(say, 'Describe the written request: --request "Letter from <company>, <date>, signed <name>"');
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY)
    return fail(say, 'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are missing in the .env file next to recover.js (copy them from Render -> Environment).');

  const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: member, error } = await db
    .from('members')
    .select('id, org_id, auth_user_id, email, full_name, active, archived_at, role:roles(id, key, name, permissions)')
    .eq('email', o.email)
    .maybeSingle();
  if (error) return fail(say, `Database error: ${error.message}`);
  if (!member) return fail(say, `Nobody with the email ${o.email} is on any staff list (also checked past staff). Add the person first, or check the spelling.`);

  const { data: org } = await db.from('organizations').select('id, name').eq('id', member.org_id).maybeSingle();
  const { data: role } = await db
    .from('roles')
    .select('id, key, name, permissions')
    .eq('org_id', member.org_id)
    .eq('key', FULL_ROLE_KEY)
    .maybeSingle();
  if (!role) return fail(say, `The care home has no "${FULL_ROLE_KEY}" role. Nothing changed.`);

  const steps = [];
  if (member.archived_at) steps.push('bring back from past staff');
  if (!member.active || member.archived_at) steps.push('restore access');
  if (member.role.key !== role.key) steps.push(`change role from ${member.role.name} to ${role.name}`);
  if (o.resetTwoFactor && member.auth_user_id) steps.push('remove the authenticator app');
  steps.push(member.auth_user_id ? 'send a "set your password" email' : 'send an invitation email');

  say(`Care home:   ${org?.name || member.org_id}`);
  say(`Person:      ${member.full_name} <${member.email}>`);
  say(`Now:         ${member.role.name}${member.archived_at ? ', LEFT (past staff)' : member.active ? '' : ', ACCESS PAUSED'}${member.auth_user_id ? ', has email sign-in' : ', no email sign-in yet'}`);
  say(`Request:     ${o.request}`);
  say('Plan:');
  for (const s of steps) say(`  - ${s}`);
  if (!o.confirm) {
    say('');
    say('NOTHING CHANGED YET. Check the plan, then run the same command again with --confirm at the end.');
    return { ok: true, dryRun: true, steps };
  }

  const now = new Date().toISOString();
  const upd = await db
    .from('members')
    .update({ active: true, archived_at: null, role_id: role.id, updated_at: now })
    .eq('id', member.id)
    .eq('org_id', member.org_id);
  if (upd.error) return fail(say, `Could not update the staff record: ${upd.error.message}. Nothing else was done.`);

  let removed = 0;
  if (o.resetTwoFactor && member.auth_user_id) {
    const list = await db.auth.admin.mfa.listFactors({ userId: member.auth_user_id });
    for (const f of list.data?.factors || []) {
      const del = await db.auth.admin.mfa.deleteFactor({ id: f.id, userId: member.auth_user_id });
      if (!del.error) removed++;
    }
  }

  let mail;
  if (member.auth_user_id) mail = await db.auth.resetPasswordForEmail(member.email, { redirectTo: INVITE_REDIRECT_URL });
  else mail = await db.auth.admin.inviteUserByEmail(member.email, { redirectTo: INVITE_REDIRECT_URL, data: { full_name: member.full_name } });
  const mailOk = !mail?.error;

  await db.from('audit_log').insert({
    org_id: member.org_id,
    actor_type: 'support',
    actor_id: null,
    action: 'support.recovery',
    detail: { memberId: member.id, request: o.request, steps, authenticatorRemoved: removed, emailSent: mailOk },
  });

  // Warning e-mail to everyone with full access (only if Brevo is set up in this .env too).
  if (process.env.BREVO_API_KEY && process.env.NOTIFY_FROM_EMAIL) {
    const { data: all } = await db
      .from('members')
      .select('email, full_name, active, archived_at, role:roles(permissions)')
      .eq('org_id', member.org_id);
    const to = (all || []).filter((m) => m.active && !m.archived_at && m.email && m.role.permissions.includes('org.manage'));
    for (const m of to) {
      await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          sender: { email: process.env.NOTIFY_FROM_EMAIL, name: process.env.NOTIFY_FROM_NAME || 'Handover' },
          to: [{ email: m.email }],
          subject: `Handover: supplier recovery for ${member.full_name}`,
          textContent:
            `The Handover supplier gave ${member.full_name} full access again (${role.name}), on the written request: ${o.request}.\n\n` +
            `If you did not expect this, contact the care home's owner and the supplier straight away.\n\nHandover`,
        }),
      }).catch(() => {});
    }
  }

  say('');
  say(`DONE. ${member.full_name} has full access again (${role.name}).`);
  say(mailOk
    ? `An email was sent to ${member.email}. They open the link, choose a password, and set up the authenticator app in My account.`
    : `The email could NOT be sent (${mail.error.message}). Run the command again in a minute.`);
  say('This is recorded in the Activity log as "Supplier recovery".');
  return { ok: true, dryRun: false, steps, mailOk, removed };
}

function fail(say, text) {
  say(`STOPPED: ${text}`);
  process.exitCode = 1;
  return { ok: false, error: text };
}

module.exports = { main };
if (require.main === module) main(process.argv.slice(2)).catch((e) => fail(console.log, e.message));

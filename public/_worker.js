/**
 * STACKDEALS OFFERWALL v2.0 - Cloudflare Pages Worker (_worker.js)
 * Subdomain: offers.getstackdeals.xyz
 * Networks: OGAds (Phase 1) / BitLabs (Phase 2) / CPAlead (Phase 3)
 * Shares ONE D1 database ("stackdeals-db") with the main giveaway worker.
 * Bindings: DB -> D1 stackdeals-db | OFFER_CACHE -> KV
 * Secrets: SESSION_SECRET (same as main), SHARED_API_KEY (same as main),
 *          POSTBACK_SECRET, MAIN_API_URL, network keys.
 */

const DATACENTER_ASN_KEYWORDS = ['amazon', 'aws', 'google cloud', 'digitalocean', 'hetzner', 'ovh', 'linode', 'vultr', 'm247', 'choopa', 'leaseweb', 'contabo', 'hostinger'];
const BLOCKED_KEYWORDS = ['survey', 'quiz', 'level', 'deposit', 'purchase', 'trial', 'subscription', 'quote', 'credit score', 'mortgage', 'insurance'];
const FAST_ACTION_BOOST_WORDS = ['install', 'open', 'sign up', 'signup', 'register', 'zip', 'sweepstakes', 'win'];

const json = (data, headers, status = 200) => new Response(JSON.stringify(data), {
  status, headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers || {}),
});
async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function hmac(key, text) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function getSettings(env) {
  const out = { points_per_dollar: 100, min_payout_usd: 0.2, offer_daily_cap: 10, offer_ip_daily_cap: 6, offerwall_enabled: true, offerwall_kill_switch: false, offer_cache_ttl_seconds: 90, network_ogads_enabled: true, network_bitlabs_enabled: false, network_cpalead_enabled: false, diminishing_returns_enabled: true, diminishing_t2_start: 5, diminishing_t2_mult: 0.5, diminishing_t3_start: 9, diminishing_t3_mult: 0.25, double_points_enabled: false };
  try {
    const rows = await env.DB.prepare('SELECT key, value, type FROM settings').all();
    for (const r of rows.results || []) {
      if (!(r.key in out)) continue;
      out[r.key] = r.type === 'number' ? Number(r.value) : r.type === 'boolean' ? r.value === 'true' : r.value;
    }
  } catch (e) { console.error('[settings]', e.message); }
  return out;
}
async function verifyHandoff(env, url) {
  const uid = (url.searchParams.get('uid') || '').trim().toLowerCase();
  const t = url.searchParams.get('t') || '';
  const sig = url.searchParams.get('sig') || '';
  if (!uid || !t || !sig) return null;
  if (Number(t) < Math.floor(Date.now() / 1000)) return null;
  if ((await hmac(env.SESSION_SECRET, uid + '.' + t)) !== sig) return null;
  return uid;
}
function corsFor(request) {
  const origin = request.headers.get('Origin') || '';
  const allow = ['https://getstackdeals.xyz', 'https://www.getstackdeals.xyz', 'https://offers.getstackdeals.xyz'].includes(origin) ? origin : 'https://getstackdeals.xyz';
  return { 'Access-Control-Allow-Origin': allow, 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}
async function fetchWithTimeout(url, opts, ms = 6000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, Object.assign({ signal: ctrl.signal }, opts || {})); }
  finally { clearTimeout(timer); }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsFor(request);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      if (url.pathname === '/api/offers' && request.method === 'GET') return await handleGetOffers(request, env, cors);
      if (url.pathname === '/api/postback') return await handlePostback(request, env, ctx);
      if (url.pathname === '/api/click' && request.method === 'GET') return await handleClick(request, env, cors);
      if (url.pathname === '/api/status' && request.method === 'GET') return await handleStatus(request, env, cors);
    } catch (e) {
      console.error('[ow:fatal]', e.message, e.stack);
      return json({ ok: false, error: 'Server error.' }, cors, 500);
    }
    return env.ASSETS.fetch(request);
  },
};

// ============================ OFFERS FEED ============================
async function handleGetOffers(request, env, cors) {
  const url = new URL(request.url);
  const S = await getSettings(env);
  if (!S.offerwall_enabled || S.offerwall_kill_switch) return json({ paused: true, offers: [] }, cors);

  const uid = await verifyHandoff(env, url);
  if (!uid) return json({ handoff_invalid: true, offers: [] }, cors);

  const cf = request.cf || {};
  const country = (cf.country || request.headers.get('CF-IPCountry') || 'US').toUpperCase();
  const asOrg = (cf.asOrganization || '').toLowerCase();
  if (country === 'T1' || country === 'XX') return json({ blocked: true, reason: 'Anonymous network blocked.', offers: [] }, cors);
  if (DATACENTER_ASN_KEYWORDS.some((kw) => asOrg.includes(kw))) return json({ blocked: true, reason: 'VPN/Datacenter IP detected. Disable your VPN to unlock tasks.', offers: [] }, cors);

  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  let device = 'desktop';
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) device = 'ios';
  else if (ua.includes('android')) device = 'android';

  // Per-user daily cap (point_ledger is shared with the main worker)
  const startToday = Math.floor(Date.now() / 86400000) * 86400;
  const countRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM point_ledger WHERE entrant_id = ? AND source_type = 'offerwall' AND created_at >= ?").bind(uid, startToday).first();
  const completionsToday = countRow?.c ?? 0;
  if (completionsToday >= S.offer_daily_cap) {
    return json({ device, country, cap_reached: true, offers: [], message: 'Daily task limit reached! Come back tomorrow — or refer a friend for entries right now.' }, cors);
  }
  // Per-IP daily cap
  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  const ipHash = (await sha256(ip + ':' + env.SESSION_SECRET)).slice(0, 16);
  const ipRow = await env.DB.prepare('SELECT COUNT(*) AS c FROM conversions WHERE ip_hash = ? AND created_at >= ?').bind(ipHash, startToday).first();
  if ((ipRow?.c ?? 0) >= S.offer_ip_daily_cap) return json({ device, country, blocked: true, reason: 'This network has reached its daily limit. Try again tomorrow.', offers: [] }, cors);

  // Cached multi-network feed
  const cacheKey = 'feed:' + country + ':' + device;
  let rawOffers = null;
  if (env.OFFER_CACHE) {
    const cached = await env.OFFER_CACHE.get(cacheKey, { type: 'json' });
    if (cached && cached.neg !== 1) rawOffers = cached;
  }
  if (!rawOffers) {
    const userIp = ip;
    const rawUa = request.headers.get('User-Agent') || '';
    const [ogads, bitlabs, cpalead] = await Promise.all([
      (env.OGADS_API_KEY && S.network_ogads_enabled) ? fetchOGAds(env.OGADS_API_KEY, userIp, rawUa, device) : Promise.resolve([]),
      (env.BITLABS_APP_TOKEN && S.network_bitlabs_enabled) ? fetchBitLabs(env.BITLABS_APP_TOKEN, device) : Promise.resolve([]),
      (env.CPALEAD_ID && S.network_cpalead_enabled) ? fetchCPAlead(env.CPALEAD_ID, country, device) : Promise.resolve([]),
    ]);
    rawOffers = [...cpalead, ...ogads, ...bitlabs];
    if (env.OFFER_CACHE) {
      if (rawOffers.length > 0) await env.OFFER_CACHE.put(cacheKey, JSON.stringify(rawOffers), { expirationTtl: S.offer_cache_ttl_seconds });
      else await env.OFFER_CACHE.put(cacheKey, JSON.stringify({ neg: 1 }), { expirationTtl: 30 }); // negative cache
    }
  }

  // Already-completed offers for this user
  const doneRows = await env.DB.prepare("SELECT offer_id FROM conversions WHERE entrant_id = ? AND status = 'credited'").bind(uid).all();
  const completedIds = new Set((doneRows.results || []).map((r) => r.offer_id));

  const dedup = new Map();
  for (const offer of rawOffers) {
    if (completedIds.has(offer.id)) continue;
    if (offer.payout_usd < S.min_payout_usd) continue;
    const blob = (offer.title + ' ' + offer.description).toLowerCase();
    if (BLOCKED_KEYWORDS.some((b) => blob.includes(b))) continue;
    const norm = offer.title.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 18);
    const existing = dedup.get(norm);
    if (!existing || offer.payout_usd > existing.payout_usd_raw) {
      const fastBoost = FAST_ACTION_BOOST_WORDS.some((w) => blob.includes(w)) ? 1.25 : 1.0;
      const base = Math.max(25, Math.round(offer.payout_usd * S.points_per_dollar));
      dedup.set(norm, Object.assign({}, offer, { payout_usd_raw: offer.payout_usd, points: base, rank_score: offer.payout_usd * fastBoost }));
    }
  }
  // Apply the user's CURRENT multiplier so displayed points are truthful
  let mult = 1;
  if (S.diminishing_returns_enabled) {
    const nth = completionsToday + 1;
    if (nth >= S.diminishing_t3_start) mult = S.diminishing_t3_mult;
    else if (nth >= S.diminishing_t2_start) mult = S.diminishing_t2_mult;
  }
  if (S.double_points_enabled) mult *= 2;
  const offers = Array.from(dedup.values())
    .sort((a, b) => b.rank_score - a.rank_score)
    .slice(0, 8)
    .map((o) => ({
      id: o.id, network: o.network, title: o.title, description: o.description, icon: o.icon,
      points: Math.max(1, Math.round(o.points * mult)),
      est_time: device === 'desktop' ? '~60 sec' : '~90 sec',
      click_url: buildTrackedUrl(o, uid),
    }));
  return json({ device, country, offers, offers_today: completionsToday, daily_cap: S.offer_daily_cap, double_points: S.double_points_enabled }, cors);
}

// ============================ NETWORK ADAPTERS ============================
async function fetchCPAlead(pubId, country, device) {
  try {
    const apiUrl = 'https://cpalead.com/dashboard/reports/campaign_json.php?id=' + encodeURIComponent(pubId) + '&country=' + country + '&incent=1';
    const res = await fetchWithTimeout(apiUrl);
    if (!res.ok) return [];
    const data = await res.json();
    const list = Array.isArray(data) ? data : (data.offers || []);
    return list
      .filter((o) => {
        const plat = String(o.platform || o.device || '').toLowerCase();
        if (device === 'ios') return plat.includes('ios') || plat.includes('iphone') || plat === '';
        if (device === 'android') return plat.includes('android') || plat === '';
        return !plat.includes('ios') && !plat.includes('iphone') && !plat.includes('android');
      })
      .map((o) => ({
        id: 'cpalead_' + (o.campid || o.campaign_id || o.id),
        network: 'cpalead',
        title: o.title || o.campaign || 'Quick Action',
        description: o.description || 'Complete the quick action to unlock entries.',
        payout_usd: parseFloat(String(o.payout || '0').replace(/[^0-9.]/g, '')) || 0,
        icon: o.creative || o.image || '',
        base_url: o.link || o.url || '',
      }));
  } catch (e) { console.error('[cpalead]', e.message); return []; }
}
async function fetchOGAds(apiKey, ip, ua, device) {
  try {
    const apiUrl = 'https://unlockcontent.net/api/v2?ip=' + encodeURIComponent(ip) + '&user_agent=' + encodeURIComponent(ua) + '&ctype=1&max=15';
    const res = await fetchWithTimeout(apiUrl, { headers: { 'Authorization': 'Bearer ' + apiKey } });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.offers || [])
      .filter((o) => {
        const plat = String(o.device || o.platform || '').toLowerCase();
        if (!plat) return true;
        if (device === 'ios') return plat.includes('ios') || plat.includes('iphone');
        if (device === 'android') return plat.includes('android');
        return !plat.includes('ios') && !plat.includes('android');
      })
      .map((o) => ({
        id: 'ogads_' + o.offerid,
        network: 'ogads',
        title: o.name_short || o.name || 'Quick Action',
        description: o.adcopy || 'Install & open, or complete the quick registration.',
        payout_usd: parseFloat(String(o.payout || '0').replace(/[^0-9.]/g, '')) || 0,
        icon: o.picture || '',
        base_url: o.link || '',
      }));
  } catch (e) { console.error('[ogads]', e.message); return []; }
}
async function fetchBitLabs(appToken, device) {
  try {
    const platform = device === 'ios' ? 'IOS' : device === 'android' ? 'ANDROID' : 'WEB';
    const apiUrl = 'https://api.bitlabs.ai/v2/client/offers?platform=' + platform;
    const res = await fetchWithTimeout(apiUrl, { headers: { 'X-Api-Token': appToken, 'X-User-Id': 'stackdeals-feed' } });
    if (!res.ok) return [];
    const data = await res.json();
    const list = (data.data && data.data.offers) ? data.data.offers : (data.offers || []);
    return list
      .filter((o) => !o.events || o.events.length <= 1) // drop multi-event grinders
      .map((o) => ({
        id: 'bitlabs_' + o.id,
        network: 'bitlabs',
        title: o.anchor || o.name || 'Quick Task',
        description: o.description || 'Complete the fast task to earn entries.',
        payout_usd: parseFloat(String(o.payout_usd || o.payout || '0').replace(/[^0-9.]/g, '')) || 0,
        icon: o.icon_url || o.image || '',
        base_url: o.click_url || o.url || '',
      }));
  } catch (e) { console.error('[bitlabs]', e.message); return []; }
}
function buildTrackedUrl(offer, uid) {
  if (!offer.base_url) return '#';
  try {
    const u = new URL(offer.base_url);
    const encoded = btoa(uid);
    if (offer.network === 'cpalead') { u.searchParams.set('subid', encoded); u.searchParams.set('subid2', offer.id); }
    else if (offer.network === 'ogads') { u.searchParams.set('aff_sub', encoded); u.searchParams.set('aff_sub2', offer.id); }
    else if (offer.network === 'bitlabs') { u.searchParams.set('subid', encoded); }
    return u.toString();
  } catch { return offer.base_url; }
}

// ============================ CLICK TRACKING ============================
async function handleClick(request, env, cors) {
  const url = new URL(request.url);
  const uid = await verifyHandoff(env, url);
  if (!uid) return json({ ok: false }, cors);
  const network = String(url.searchParams.get('network') || '').slice(0, 20);
  const offerId = String(url.searchParams.get('offer_id') || '').slice(0, 60);
  if (!network || !offerId) return json({ ok: false }, cors);
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const ipHash = ip ? (await sha256(ip + ':' + env.SESSION_SECRET)).slice(0, 16) : '';
  await env.DB.prepare('INSERT INTO offer_clicks (entrant_id, network, offer_id, ip_hash, clicked_at) VALUES (?,?,?,?,?)')
    .bind(uid, network, offerId, ipHash, Math.floor(Date.now() / 1000)).run();
  return json({ ok: true }, cors);
}

// ============================ POSTBACK ============================
async function handlePostback(request, env, ctx) {
  const url = new URL(request.url);
  const pw = url.searchParams.get('password') || url.searchParams.get('secret');
  if (!env.POSTBACK_SECRET || pw !== env.POSTBACK_SECRET) return new Response('Unauthorized', { status: 401 });

  const network = (url.searchParams.get('network') || '').toLowerCase();
  if (!['ogads', 'bitlabs', 'cpalead'].includes(network)) return new Response('Unknown network', { status: 400 });

  const leadId = url.searchParams.get('lead_id') || url.searchParams.get('tx_id') || url.searchParams.get('transaction_id') || url.searchParams.get('click_id');
  const rawSub = url.searchParams.get('subid') || url.searchParams.get('aff_sub') || url.searchParams.get('sub1');
  const rawOffer = url.searchParams.get('offer_id') || url.searchParams.get('campaign_id') || url.searchParams.get('oid') || 'unknown';
  const payoutRaw = String(url.searchParams.get('payout') || url.searchParams.get('amount') || '0').replace(/[^0-9.\-]/g, '');
  const payout = parseFloat(payoutRaw);
  const statusParam = url.searchParams.get('status') || '1';
  if (!leadId || !rawSub) return new Response('Missing lead_id or subid', { status: 400 });
  if (!isFinite(payout) || Math.abs(payout) < 0.01 || Math.abs(payout) > 50) return new Response('Bad payout', { status: 400 });

  let userId = rawSub;
  try { userId = atob(rawSub).trim().toLowerCase(); } catch (e) { userId = rawSub.trim().toLowerCase(); }
  if (!/^[0-9a-f-]{36}$/.test(userId)) return new Response('Bad subid', { status: 400 });

  const S = await getSettings(env);
  const offerId = network + '_' + rawOffer;
  const now = Math.floor(Date.now() / 1000);

  // Reversal / chargeback
  if (statusParam === '2' || payout < 0) {
    const existing = await env.DB.prepare('SELECT entrant_id, points_awarded, status FROM conversions WHERE lead_id = ?').bind(leadId).first();
    if (existing && existing.status === 'credited') {
      await env.DB.prepare("UPDATE conversions SET status = 'reversed', synced = 1 WHERE lead_id = ?").bind(leadId).run();
      ctx.waitUntil(creditMain(env, '/api/reverse-points', { entrant_id: existing.entrant_id, lead_id: leadId, points: existing.points_awarded, network }));
    }
    return new Response('OK', { status: 200 });
  }

  const basePoints = Math.max(25, Math.round(payout * S.points_per_dollar));
  const insert = await env.DB.prepare(
    'INSERT OR IGNORE INTO conversions (lead_id, network, entrant_id, offer_id, offer_title, payout_usd, base_points, points_awarded, status, synced, ip_hash, created_at) VALUES (?,?,?,?,?,?,?,0,\'credited\',0,?,?)'
  ).bind(leadId, network, userId, offerId, '', payout, basePoints, '', now).run();

  if (insert.meta.changes === 1) {
    ctx.waitUntil((async () => {
      const res = await creditMain(env, '/api/credit-points', { lead_id: leadId, entrant_id: userId, network, payout_usd: payout, points: basePoints, offer_id: offerId });
      if (res && res.ok) {
        await env.DB.prepare('UPDATE conversions SET points_awarded = ?, synced = 1 WHERE lead_id = ?').bind(res.awarded, leadId).run();
      }
      // Non-ok reasons (duplicate/daily_cap/campaign_ended) are handled by main; leave synced=0 only for transport failures.
      if (res && !res.ok && res.reason && res.reason !== 'transport') {
        await env.DB.prepare('UPDATE conversions SET synced = 1 WHERE lead_id = ?').bind(leadId).run();
      }
    })());
  }
  return new Response('OK', { status: 200 });
}
async function creditMain(env, path, payload) {
  const base = (env.MAIN_API_URL || '').replace(/\/$/, '');
  if (!base) return null;
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetchWithTimeout(base + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Api-Key': env.SHARED_API_KEY || '' },
        body: JSON.stringify(payload),
      }, 8000);
      const d = await r.json().catch(() => ({}));
      if (r.ok && d.ok) return d;
      if (d.reason) return d; // business rejection - no retry
    } catch (e) { /* retry */ }
    await new Promise((res) => setTimeout(res, 500 * Math.pow(2, i)));
  }
  return { reason: 'transport' };
}

// ============================ STATUS ============================
async function handleStatus(request, env, cors) {
  const url = new URL(request.url);
  const uid = await verifyHandoff(env, url);
  if (!uid) return json({ handoff_invalid: true }, cors);
  const [participants, me, recentRows] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS c FROM entrants WHERE verified = 1 AND email_invalid = 0').first(),
    env.DB.prepare('SELECT total_points FROM entrants WHERE id = ?').bind(uid).first(),
    env.DB.prepare("SELECT c.points_awarded, c.created_at, e.email FROM conversions c JOIN entrants e ON e.id = c.entrant_id WHERE c.status = 'credited' AND c.points_awarded > 0 ORDER BY c.created_at DESC LIMIT 6").all(),
  ]);
  const recent = (recentRows.results || []).map((r) => {
    const name = r.email && r.email.includes('@') ? r.email.split('@')[0].slice(0, 4) + '***' : 'Member';
    return { name, points: r.points_awarded, ago: Math.max(1, Math.round((Date.now() / 1000 - r.created_at) / 60)) };
  });
  return json({ participants: participants?.c ?? 0, user_points: me?.total_points ?? 0, recent_activity: recent }, cors);
}

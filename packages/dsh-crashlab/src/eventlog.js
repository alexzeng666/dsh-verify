/**
 * L2 attribution: Application Error / .NET Runtime / WER in the Windows event log.
 *
 * When the system reaps a process the minidump may be unavailable (the process is already gone),
 * but the event log still records "which module, what exception code, how large an offset". Read it
 * with wevtutil, no third-party dependencies.
 *
 * Everything is fail-open: if the log cannot be read, return { found: false }; conclusions from
 * other layers are unaffected.
 */
import { execFile } from 'node:child_process';

const MAX_EVENTS = 40;
const WINDOW_MS = 15 * 60 * 1000;

// wevtutil XPath: list the Provider predicates with or @Name=… inside one predicate; nesting
// Provider[…] does not work.
const QUERY =
  "*[System[Provider[@Name='Application Error' or @Name='.NET Runtime' or @Name='Windows Error Reporting']]]";

const ATTR = (block, name) => {
  const match = new RegExp(`${name}=['"]([^'"]*)['"]`).exec(block);
  return match ? match[1] : '';
};

function xmlEvents(xml) {
  const events = [];
  const blocks = xml.split('<Event ').slice(1);
  for (const block of blocks) {
    const provider = ATTR(block, 'Provider Name');
    const time = ATTR(block, 'SystemTime');
    const eventId = /<EventID[^>]*>(\d+)</.exec(block)?.[1] ?? '';
    const data = [...block.matchAll(/<Data[^>]*>([\s\S]*?)<\/Data>/g)].map((match) => match[1].trim());
    events.push({ provider, time, event_id: Number(eventId), data });
  }
  return events;
}

function decodeXml(text) {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function queryEvents() {
  return new Promise((done) => {
    if (process.platform !== 'win32') {
      done({ ok: false, error: 'the event log only exists on Windows' });
      return;
    }
    execFile(
      'wevtutil',
      ['qe', 'Application', `/c:${MAX_EVENTS}`, '/rd:true', '/f:xml', `/q:${QUERY}`],
      { windowsHide: true, timeout: 20_000, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout) => {
        if (error) {
          done({ ok: false, error: error.message });
          return;
        }
        done({ ok: true, events: xmlEvents(String(stdout ?? '')) });
      },
    );
  });
}

/** Normalize exception codes to the 0xC0000005 form. */
function normalizeCode(value) {
  const text = String(value ?? '').trim();
  if (text === '') return '';
  if (/^0x[0-9a-f]+$/i.test(text)) return `0x${text.slice(2).toUpperCase()}`;
  if (/^[0-9a-f]{8}$/i.test(text)) return `0x${text.toUpperCase()}`;
  return text;
}

/** The Data fields mean different things per provider; pick them by known layout. */
function shape(provider, data) {
  if (provider === 'Windows Error Reporting') {
    return { app: data[5] ?? '', module: data[8] ?? '', exception_code: normalizeCode(data[11]), offset: data[12] ?? '' };
  }
  if (provider === '.NET Runtime') {
    const code = data.map(normalizeCode).find((item) => /^0x[89A-F][0-9A-F]{7}$/i.test(item)) ?? '';
    return { app: data[0] ?? '', module: data[3] ?? '', exception_code: code, offset: '' };
  }
  // Application Error (EventID 1000)
  return {
    app: data[0] ?? '',
    module: data[3] ?? '',
    exception_code: normalizeCode(data[6]),
    offset: data[7] ?? '',
    pid: Number(data[8]) || undefined,
  };
}

/**
 * Find the crash event matching the target process.
 * @param {{ image?: string, pid?: number, since?: number }} target
 */
export async function lookupCrashEvent(target) {
  const result = await queryEvents();
  if (!result.ok) return { found: false, error: result.error };

  const image = (target.image ?? '').toLowerCase();
  const since = target.since ?? Date.now() - WINDOW_MS;
  const pidText = Number.isFinite(target.pid) ? String(target.pid) : '';

  for (const event of result.events) {
    const time = Date.parse(event.time);
    if (Number.isFinite(time) && time < since) continue;
    const data = event.data.map(decodeXml);
    const info = shape(event.provider, data);
    const appMatches = image !== '' && info.app.toLowerCase() === image;
    const pidMatches = pidText !== '' && data.includes(pidText);
    if (!appMatches && !pidMatches) continue;
    return { found: true, provider: event.provider, time: event.time, ...info };
  }
  return { found: false };
}

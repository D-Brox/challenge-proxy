// One line per event, with optional structured fields, so the container's log is greppable
// and a request can be followed from the HTTP edge down into the oracle.
//
// LOG_LEVEL picks the threshold: error < warn < info < debug (default info). LOG_BODY=1 adds
// the body of successful /request responses, which is large and rarely wanted.
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const threshold = LEVELS[process.env.LOG_LEVEL] ?? LEVELS.info;
const includeBody = /^(1|true)$/i.test(process.env.LOG_BODY || '');

function emit(level, message, fields) {
  if (LEVELS[level] > threshold) return;
  const line = { t: new Date().toISOString(), level, msg: message };
  if (fields && Object.keys(fields).length) Object.assign(line, fields);
  const out = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  out.write(`${JSON.stringify(line)}\n`);
}

export const log = {
  error: (message, fields) => emit('error', message, fields),
  warn: (message, fields) => emit('warn', message, fields),
  info: (message, fields) => emit('info', message, fields),
  debug: (message, fields) => emit('debug', message, fields),
};

export const wantsBody = () => includeBody;

export const isDebug = () => LEVELS.debug <= threshold;

/** Trims a body down to something safe to put in a log line. */
export function bodySummary(text, limit = 120) {
  if (!includeBody) return { bytes: text.length };
  return { bytes: text.length, head: text.slice(0, limit) };
}
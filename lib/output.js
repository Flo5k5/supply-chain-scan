// Zero-dependency, cross-platform terminal output.
// Colors honor NO_COLOR / FORCE_COLOR / TTY; symbols fall back to ASCII on the
// Windows legacy console (cmd.exe), which mangles unicode.

const isWin = process.platform === 'win32';

// Read env lazily so `--no-color` (which sets NO_COLOR before output runs) works.
function colorOn() {
  if (process.env.NO_COLOR) return false; // https://no-color.org
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return process.stdout.isTTY === true;
}

// Windows Terminal (WT_SESSION) handles unicode; legacy cmd.exe does not.
function unicodeOn() {
  return process.stdout.isTTY === true && (!isWin || !!process.env.WT_SESSION);
}

const CODES = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function paint(text, code) {
  return colorOn() ? `${code}${text}${CODES.reset}` : text;
}

export const c = {
  bold: (s) => paint(s, CODES.bold),
  dim: (s) => paint(s, CODES.dim),
  red: (s) => paint(s, CODES.red),
  green: (s) => paint(s, CODES.green),
  yellow: (s) => paint(s, CODES.yellow),
  cyan: (s) => paint(s, CODES.cyan),
  gray: (s) => paint(s, CODES.gray),
};

// status → glyph + color
const GLYPH = {
  ok: { u: '✓', a: 'OK', color: c.green },
  warn: { u: '⚠', a: '!', color: c.yellow },
  fail: { u: '✗', a: 'X', color: c.red },
  skip: { u: '–', a: '-', color: c.gray },
  info: { u: 'ℹ', a: 'i', color: c.cyan },
};

export function symbol(status) {
  const g = GLYPH[status] || GLYPH.info;
  return g.color(unicodeOn() ?g.u : g.a);
}

const RULE = '────────────────────────────────────────────────────────────';

export function header(title, dir) {
  const lock = unicodeOn() ? '🔒' : '#';
  process.stdout.write(`${lock} ${c.bold(title)}\n`);
  process.stdout.write(`   ${c.dim(dir)}\n`);
  process.stdout.write(c.gray(RULE) + '\n');
}

// Print one check's result: a titled section then its lines.
export function section(result) {
  const arrow = unicodeOn() ?'▶' : '>';
  process.stdout.write(`\n${c.cyan(arrow)} ${c.bold(result.title)}\n`);
  for (const ln of result.lines) {
    process.stdout.write(`  ${symbol(ln.status)} ${ln.text}\n`);
  }
}

export function verdict(code, name) {
  process.stdout.write('\n' + c.gray(RULE) + '\n');
  if (code === 0) {
    const m = unicodeOn() ?'✅' : '[OK]';
    process.stdout.write(`${m} ${c.green('CLEAN')} — safe to start working on ${c.bold(name)}.\n`);
  } else if (code === 1) {
    const m = unicodeOn() ?'⚠️ ' : '[!]';
    process.stdout.write(`${m} ${c.yellow('REVIEW')} — see the ${symbol('warn')}/${symbol('fail')} lines above before installing or updating dependencies.\n`);
  } else {
    const m = unicodeOn() ?'🛠 ' : '[setup]';
    process.stdout.write(`${m} ${c.cyan('SETUP')} — install the missing tool, then re-run.\n`);
  }
}

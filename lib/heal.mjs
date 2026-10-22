// Registry self-heal: re-extract lib/mapper-registry.json from the live apicore chunk.
//
// The registry maps the site's mangled view-model keys back to the camel JSON the
// extension parses, and everything mangled inside changes when the site re-obfuscates -
// which has happened twice in one afternoon. Until now that meant a human replaying
// .scratch/map-extract.py by hand. This module is that pipeline, ported to Node so the
// proxy can run it against the served bundle itself:
//
//   1. string table    - the obfuscator's lookup table, its decoder and the rotation
//                        self-check are pulled out of the chunk; the rotation is solved
//                        by brute-forcing the shift until the checksum expression holds
//                        (exactly one shift ever does, and a miss fails loudly).
//   2. mapper scopes   - every `function name(arg){const t=decoder;...}` (and the anon
//                        closures inside the store wrappers) is parsed into a spec tree:
//                        prop / child / list / cond / concat / arrowList, with spreads
//                        ({...Km(Y)}) expanded into their parent composite.
//   3. roles           - the three composites the extension needs are picked by the
//                        route tables' semantic anchors ("manga","chapters"; ...) and
//                        cross-checked against shape signatures; a disagreement is fatal.
//
// Nothing here runs site code beyond the table decoder itself, sandboxed. A registry
// extracted by this module is validated against a live request by the oracle before it
// replaces the served one - extraction correctness is proven, not assumed.
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import vm from 'node:vm';

// ------------------------------------------------------------------ small helpers

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const fullmatch = (body, flags, s) => {
  const m = new RegExp('^(?:' + body + ')$', flags).exec(s);
  return m;
};

function braceEnd(text, start) {
  let depth = 0;
  let inStr = null;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inStr !== null) {
      if (c === inStr && text[i - 1] !== '\\') inStr = null;
    } else if (c === '"' || c === "'") {
      inStr = c;
    } else if (c === '{') {
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function splitTop(expr) {
  const parts = [];
  let depth = 0;
  let inStr = null;
  let last = 0;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (inStr !== null) {
      if (c === inStr && (i === 0 || expr[i - 1] !== '\\')) inStr = null;
    } else if (c === '"' || c === "'") {
      inStr = c;
    } else if (c === '{' || c === '(' || c === '[') {
      depth++;
    } else if (c === '}' || c === ')' || c === ']') {
      depth--;
    } else if (c === ',' && depth === 0) {
      parts.push(expr.slice(last, i).trim());
      last = i + 1;
    }
  }
  const tail = expr.slice(last).trim();
  if (tail) parts.push(tail);
  return parts;
}

// ------------------------------------------------------------------ 1. string table

/**
 * Pulls the obfuscator's kit out of the chunk: the lookup-table function, the decoder
 * function and its offset, and the rotation self-check expression. Returns the decoded
 * table (string-table arg -> string) plus the names needed later (global decoder alias,
 * decoder name).
 */
function recoverTable(src) {
  // table function: function X(){const T=[...];return(X=function(){return T})()}
  let tableFn = null;
  let tableArr = null;
  const tableRe = /function ([\w$]+)\(\)\{const ([\w$]+)=\[/g;
  for (let m; (m = tableRe.exec(src)); ) {
    const start = m.index;
    const end = braceEnd(src, start);
    if (end < 0) continue;
    const body = src.slice(start, end + 1);
    const arrMatch = /const [\w$]+=\[([\s\S]*)\];return/.exec(body);
    if (!arrMatch) continue;
    const items = arrMatch[1].match(/"(?:[^"\\]|\\.)*"/g) || [];
    if (!tableArr || items.length > tableArr.length) {
      tableFn = m[1];
      tableArr = items.map((s) => s.slice(1, -1));
    }
  }
  if (!tableArr) throw new Error('no string table found in chunk');

  // decoder: function D(A,R){A-=OFF;const T=TABLEFN();...}
  const decRe = /function ([\w$]+)\(([\w$]+),[\w$]+\)\{\2-=(\d+);/;
  const dm = decRe.exec(src);
  if (!dm) throw new Error('no string decoder found in chunk');
  const [, decName, decArg, offStr] = dm;
  const off = Number(offStr);
  const decStart = dm.index;
  const decEnd = braceEnd(src, decStart);
  if (decEnd < 0) throw new Error('decoder body not balanced');
  let decBody = src.slice(decStart, decEnd + 1);
  // the decoder reads the table through its own accessor; bind it to our array
  const tblRef = new RegExp('const ([\\w$]+)=' + escapeRe(tableFn) + '\\(\\);').exec(decBody);
  const tblLocal = tblRef ? tblRef[1] : null;

  // rotation self-check: !function(){const AL=D,TB=TABLE();for(;;)try{if(EXPR)break;...
  const rotRe = new RegExp(
    '!function\\(\\)\\{const ([\\w$]+)=' + escapeRe(decName) + ',[\\w$]+=[\\w$]+\\(\\);for\\(;;\\)try\\{if\\((.*?)\\)break;',
  );
  const rm = rotRe.exec(src);
  if (!rm) throw new Error('no rotation self-check found in chunk');
  const aliasName = rm[1];
  const expr = rm[2];
  const magic = /^(\d+)=/.exec(expr);
  if (!magic) throw new Error('rotation checksum not understood: ' + expr.slice(0, 60));

  // Solve the rotation: shift the table until the checksum expression holds. The site's
  // own IIFE does the same loop; driving it shift-by-shift here makes convergence
  // observable instead of trusting a copied IIFE to run identically.
  const table = tableArr.slice();
  const sandbox = {
    parseInt,
    String,
    decodeURIComponent,
    Array,
    Math,
  };
  sandbox[tableFn] = () => table;
  sandbox[decName] = new Function(
    tableFn,
    `"use strict";return (${decBody.replace(new RegExp('(?<![\\w$.])' + escapeRe(tableFn) + '\\(', 'g'), tableFn + '(')})`,
  )(sandbox[tableFn]);
  if (tblLocal && tblLocal !== tableFn) sandbox[tblLocal] = table;
  sandbox[aliasName] = sandbox[decName];
  const ctx = vm.createContext(sandbox);
  let solved = -1;
  for (let shift = 0; shift < tableArr.length; shift++) {
    let ok = false;
    try {
      ok = vm.runInContext(expr, ctx, { timeout: 1000 }) === true;
    } catch {
      ok = false;
    }
    if (ok) {
      solved = shift;
      break;
    }
    table.push(table.shift());
  }
  if (solved < 0) throw new Error('rotation never converged (checksum ' + magic[1] + ')');

  const out = {};
  for (let i = 0; i < table.length; i++) {
    let v;
    try {
      v = vm.runInContext(decName + '(' + (off + i) + ')', ctx, { timeout: 1000 });
    } catch {
      continue;
    }
    if (typeof v === 'string') out[off + i] = v;
  }
  const head = /const ([\w$]+)=([\w$]+);/.exec(src.slice(0, 200));
  // The minifier re-aliases the decoder per module section (q -> s1) and per function
  // (s1 -> s6): a mapper scope opens with `const L=s1;`, referencing a name one or more
  // hops away from the decoder. Collect the whole alias closure so scope matching does
  // not depend on any single naming scheme. The module-level alias is whichever bound
  // name carries the most call sites (a header comment can push the first one out of
  // its usual place).
  const aliases = new Set([decName]);
  const bound = [];
  for (let grew = true; grew; ) {
    grew = false;
    const pat = new RegExp('(?:const|var|let)\\s+([\\w$]+)\\s*=\\s*(?:' + [...aliases].map(escapeRe).join('|') + ')\\s*[;,]', 'g');
    for (let m; (m = pat.exec(src)); ) {
      if (aliases.has(m[1])) continue;
      aliases.add(m[1]);
      bound.push(m[1]);
      grew = true;
    }
  }
  let globalAlias = decName;
  let best = -1;
  for (const name of [decName, ...bound]) {
    const uses = (src.match(new RegExp('(?<![\\w$.])' + escapeRe(name) + '\\(', 'g')) || []).length;
    if (uses > best) {
      best = uses;
      globalAlias = name;
    }
  }
  return {
    table: out,
    decName,
    globalAlias,
    aliases: [...aliases],
  };
}

/**
 * The obfuscator's newest string trick: names the code indexes like `s[bj]` resolve
 * through char-code array constants (`bj=_i(109,101,116,97)` -> "meta"), invisible to the
 * string-table decode. Resolves the constant chain and returns name -> string.
 */
export function recoverStrVars(src, aliases) {
  const A = aliases.map(escapeRe).join('|');
  const vars = {};
  // the char-code builder: NAME=(...args)=>String[DEC(...)](...args)
  let builder = null;
  const bm = new RegExp('([\\w$]+)\\s*=\\s*\\(\\.\\.\\.\\w+\\)\\s*=>\\s*String\\[(?:' + A + ')\\(').exec(src);
  if (bm) {
    builder = bm[1];
    const pat = new RegExp('\\b([\\w$]+)\\s*=\\s*' + escapeRe(builder) + '\\(\\s*((?:\\d+\\s*,\\s*)*\\d+)\\s*\\)', 'g');
    for (let g = true; g; ) {
      g = false;
      for (const v of src.matchAll(pat)) {
        if (v[1] in vars) continue;
        vars[v[1]] = String.fromCharCode(...v[2].split(/[\s,]+/).filter(Boolean).map(Number));
        g = true;
      }
      // constants built from other constants: X = a + b + "lit"
      if (Object.keys(vars).length) {
        constPiecing: for (const v of src.matchAll(new RegExp('\\b([\\w$]+)\\s*=\\s*(' + Object.keys(vars).map(escapeRe).join('|') + '|"[^"]*")((?:\\s*\\+\\s*(?:' + Object.keys(vars).map(escapeRe).join('|') + '|"[^"]*"))+)\\s*[,;]', 'g'))) {
          if (v[1] in vars) continue;
          let out = '';
          for (const piece of (v[2] + v[3]).split('+')) {
            const t = piece.trim().replace(/^"|"$/g, '');
            if (vars[t] !== undefined) out += vars[t];
            else if (/^[\w$-]+$/.test(t)) out += t;
            else continue constPiecing;
          }
          vars[v[1]] = out;
          g = true;
        }
      }
    }
  }
  return vars;
}

// ------------------------------------------------------------------ 2. mapper scopes

function buildExtractor(src, table, decName, globalAlias, extraAliases) {
  const aliases = [...new Set([...(extraAliases || []), globalAlias, decName])];
  const AL = aliases.map(escapeRe).join('|');
  const decodeIdx = (n) => {
    const v = table[n];
    return typeof v === 'string' ? v : null;
  };
  const identRe = /^[A-Za-z_$][\w$]*$/;
  const strvars = recoverStrVars(src, aliases);

  // Names invisible to the string-table decode (`s[bj]` where bj="meta") are replaced
  // with their literal so the path/prop parsing sees plain text. Quote-adjacent guard:
  // view-model keys can collide with constant names ("fj": the hid key vs fj="node").
  const subStrVars = (text) => {
    for (const [name, s] of Object.entries(strvars)) {
      if (!identRe.test(s) && s.length === 0) continue;
      text = text.replace(new RegExp('(?<![\\w$."])' + escapeRe(name) + '(?![\\w$"])', 'g'), '"' + s + '"');
    }
    return text;
  };

  const substitute = (text, local) =>
    subStrVars(text.replace(new RegExp('(?<![\\w$.])' + escapeRe(local) + '\\((\\d+)\\)', 'g'), (all, n) => {
      const v = decodeIdx(Number(n));
      return v !== null && identRe.test(v) ? '"' + v + '"' : '_IDX(' + n + ')';
    }));

  const DESTRUCT = /\{((?:\s*"(?:[^"]|\\")+"\s*:\s*[\w$]+\s*(?:,\s*)?)+)\}=(\w+)/g;
  const collectAliases = (body, arg) => {
    const aliases = {};
    for (const m of body.matchAll(DESTRUCT)) {
      if (m[2] !== arg) continue;
      for (const km of m[1].matchAll(/"([^"]+)":\s*([\w$]+)/g)) aliases[km[2]] = [arg, km[1]];
    }
    return aliases;
  };

  const rewriteAliases = (expr, arg, aliases) => {
    let e = expr.replace(/\?\.\[/g, '[').replace(/\?\./g, '.');
    for (const a of Object.keys(aliases)) {
      const prop = aliases[a][1];
      const rep = !prop ? arg : arg + '["' + prop + '"]';
      e = e.replace(new RegExp('(?<![\\w$.])' + escapeRe(a) + '(?![\\w$])', 'g'), rep);
    }
    return e;
  };

  const WRAP = /(?<![\w$.])([\w$]+)\s*=\s*Array\[["']?isArray["']?\]\(\w+\)\?[^,;]{1,40}?[:,]\s*(\w)[,;]/g;
  const PRE = /(?<![\w$.])([\w$]+)\s*=\s*([\w$]+)((?:\[[^\]\n]*\]|\.\w+)+)\s*\?\?\s*[^,;\n]{1,24}[,;\n]/g;
  const TOKEN = /\["([^"]+)"\]|\.\s*(\w+)|\[\s*_IDX\s*\((\d+)\)\s*\]|\.?\s*_IDX\s*\((\d+)\)/y;
  const word = '[\\w$]+';

  const readPath = (arg, e) => {
    e = e.trim();
    if (!e.startsWith(arg)) return null;
    const next = e[arg.length] || ' ';
    if (!/^[\[.]/.test(next)) return null;
    const rest = e.slice(arg.length);
    TOKEN.lastIndex = 0;
    const parts = [];
    let pos = 0;
    for (;;) {
      TOKEN.lastIndex = pos;
      const m = TOKEN.exec(rest);
      if (!m || m.index !== pos) break;
      if (m[1] !== undefined) parts.push(m[1]);
      else if (m[2] !== undefined) parts.push(m[2]);
      else parts.push('?idx' + (m[3] !== undefined ? m[3] : m[4]));
      pos = TOKEN.lastIndex;
    }
    if (!parts.length) return null;
    const tail = rest.slice(pos);
    if (tail && !/^\?\?[^?]*$/.test(tail.replace(/\n/g, ' ').replace(/[\s\S]*/, (x) => x))) {
      // mirror python's re.fullmatch(r'\?\?[^?]*', tail, re.S): any chars except '?'
      if (!/^\?\?[^?]*$/.test(tail)) return null;
    }
    return parts.join('.');
  };

  const parseValue = (e0, arg, aliases = {}, outer = null) => {
    const e = rewriteAliases(e0.trim(), arg, aliases);
    const A = escapeRe(arg);
    const chainOf = (x) => {
      const cands = outer === null || outer === arg ? [arg] : [arg, outer];
      for (const root of cands) {
        const p = readPath(root, rewriteAliases(x, root, aliases));
        if (p !== null) return p;
      }
      return null;
    };

    // concat: a + b
    const plus = e.lastIndexOf('+');
    if (plus > 0 && !e.includes('=>')) {
      const lp = chainOf(e.slice(0, plus).trim());
      const rp = chainOf(e.slice(plus + 1).trim());
      if (lp !== null && rp !== null) return { k: 'concat', n: rp, base: lp };
    }
    let m = fullmatch('\\{\\.\\.\\.(' + word + ')\\(' + A + '\\)\\}', 's', e);
    if (m) return { k: 'spread', name: m[1] };
    // child mapper call: FN(arg[...]) / FN(arg)
    m = fullmatch('(' + word + ')\\(' + A + '([\\s\\S]*)\\)', 's', e);
    if (m) {
      const rp = m[2] ? readPath(arg, arg + m[2]) : null;
      return rp !== null ? { k: 'child', name: m[1], path: rp } : { k: 'child', name: m[1], path: '?raw' };
    }
    // conditional child call: arg["p"]?FN(arg["p"]):nullish - the site maps a field only
    // when present, which is semantically the child spec (unm passes null through).
    m = fullmatch(
      '(' + A + '(?:\\["([\\w$]+)"\\]|\\.(\\w+))?)\\s*\\?\\s*(' + word + ')\\(\\s*\\1\\s*\\)\\s*:\\s*(?:void 0|null|undefined)',
      's',
      e,
    );
    if (m && (m[2] || m[3])) {
      return { k: 'child', name: m[4], path: m[2] || m[3] };
    }
    // conditional: arg[p]?{...}
    const cp = chainOf(e);
    m = new RegExp('^' + A + '(?:\\["([\\w$]+)"\\]|\\.(\\w+))\\?\\{').exec(e);
    if (m) {
      const key = m[1] || m[2];
      const pm = e.indexOf('{');
      const bend = braceEnd(e, pm);
      const inner = e.slice(pm + 1, bend);
      const entries = {};
      for (const q of splitTop(inner)) {
        const qm = fullmatch('"([\\w$]+)":\\s*([\\s\\S]*)', 's', q);
        if (qm) entries[qm[1]] = parseValue(qm[2], arg, aliases, outer);
        else entries['?' + q.slice(0, 24)] = { k: 'unknown', expr: q.slice(0, 80) };
      }
      // The page-side flatten applies a cond's entries to the cond VALUE (N.creator, not
      // N), so inner paths rooted at the cond's own path are stored relative to it -
      // "creator.id" would leak dotted keys into the JSON the extension parses.
      const pfx = key + '.';
      for (const k of Object.keys(entries)) {
        const s = entries[k];
        if (!s || typeof s !== 'object') continue;
        if (typeof s.n === 'string' && s.n.startsWith(pfx)) s.n = s.n.slice(pfx.length);
        if (typeof s.path === 'string' && s.path.startsWith(pfx)) s.path = s.path.slice(pfx.length);
      }
      return { k: 'cond', path: key, entries };
    }
    // list child: (arg["p"]??[])["map"](FN) / arg["p"]["map"](FN) / arg["p"].map(FN)
    m = fullmatch(
      '(?:\\()?' + A + '(\\[?["\']([\\w$]+)["\']\\]?|\\.\\w+)(?:\\?\\?\\[\\])?\\)?(?:\\.|\\[\\s*["\']?)map(?:["\']?\\s*\\])?\\((' + word + ')\\)',
      's',
      e,
    );
    if (m) return { k: 'list', path: m[2], child: m[3] };
    if (cp !== null) return { k: 'prop', n: cp };
    // inline arrow list: (arg??[])[map](y=>({...}))
    m = fullmatch('\\(' + A + '\\(?\\)?\\??\\?\\?\\[\\]\\)\\[[^\\]]+\\]\\((\\w+)=>\\(?([\\s\\S]*?)\\)?\\)$', 's', e);
    if (m && m[2].includes('{')) {
      let inner = m[2];
      if (inner.startsWith('{')) inner = inner.slice(1, inner.lastIndexOf('}'));
      const entries = {};
      for (const q of splitTop(inner)) {
        const qm = fullmatch('"([\\w$]+)":\\s*([\\s\\S]*)', 's', q);
        if (qm) entries[qm[1]] = parseValue(qm[2], m[1], aliases, outer);
      }
      return { k: 'arrowList', entries };
    }
    if (e.includes('=>')) return { k: 'arrowOther', expr: e.slice(0, 90) };
    return { k: 'unknown', expr: e.slice(0, 90) };
  };

  const parseLiteralEntries = (body, arg, aliases = {}, outer = null) => {
    const entries = {};
    const spreads = {};
    for (const pair of splitTop(body)) {
      const pm = fullmatch('"([\\w$]+)":\\s*([\\s\\S]*)', 's', pair);
      if (pm) {
        entries[pm[1]] = parseValue(pm[2], arg, aliases, outer);
        continue;
      }
      const sm = fullmatch('\\{?\\.\\.\\.([\\w$]+)\\((\\w)\\)\\}?', 's', pair);
      if (sm) spreads[sm[1]] = sm[2];
    }
    return [entries, spreads];
  };

  const collectPrelude = (b, arg, baseAliases) => {
    const out = {};
    const nb = b.replace(/\?\.\[/g, '[').replace(/\?\./g, '.');
    for (const m of nb.matchAll(WRAP)) out[m[1]] = [arg, ''];
    for (let round = 0; round < 2; round++) {
      for (const m of nb.matchAll(PRE)) {
        const [name, base, chain] = [m[1], m[2], m[3]];
        if (name in out) continue;
        let prefix;
        if (base === arg || (base in out && out[base][1] === '')) prefix = out[base] ? out[base][1] : '';
        else if (baseAliases && base in baseAliases && baseAliases[base][1]) prefix = baseAliases[base][1] + '.';
        else if (base === arg) prefix = '';
        else continue;
        const path = readPath(arg, arg + chain);
        if (path === null) continue;
        out[name] = [arg, prefix + path];
      }
    }
    return out;
  };

  const extractScopes = () => {
    const scopes = [];
    const taken = new Set();
    // Every alias declaration (`const X=ALIAS;`, possibly mid declarator list) marks a
    // mapper scope; the enclosing function is found by brace-walking back from it. This
    // covers named functions, anonymous ones, arrows, method shorthand, and scopes that
    // guard first (`if(!o)return null;const R=ALIAS;...`).
    const declPat = new RegExp('(?:const|var|let)\\s+[^;{]*?\\b([\\w$]+)\\s*=\\s*(?:' + AL + ')\\s*[,;]', 'g');
    for (let m; (m = declPat.exec(src)); ) {
      let depth = 0;
      let brace = -1;
      for (let i = m.index; i >= 0; i--) {
        const ch = src[i];
        if (ch === '}') depth++;
        else if (ch === '{') {
          if (depth === 0) { brace = i; break; }
          depth--;
        }
      }
      if (brace < 0 || taken.has(brace)) continue;
      taken.add(brace);
      const head = src.slice(Math.max(0, brace - 260), brace + 1);
      let hm = /function\s*([\w$]*)\s*\(([^)]*)\)\s*\{$/.exec(head);
      let params = null;
      let fname = null;
      if (hm) { fname = hm[1]; params = hm[2]; }
      else if ((hm = /\(([^)]*)\)\s*=>\s*\{$/.exec(head))) params = hm[1];
      else if ((hm = /(?:async\s*)?(?:["'][\w$]+["']\s*)?\((\w+)\)\s*\{$/.exec(head))) params = hm[1];
      else if ((hm = /(?:async\s*)?(\w+)\s*=>\s*\{$/.exec(head))) params = hm[1];
      if (params === null) continue;
      const end = braceEnd(src, brace);
      if (end < 0) continue;
      const parts = params.split(',').map((p) => p.split('=')[0].trim()).filter(Boolean);
      if (!parts.length) continue;
      // Anonymous scopes are named after the function-keyword position (not the brace) so
      // the composite wiring's '@anon' references line up.
      const kw = hm.index + (brace + 1 - head.length);
      const name = fname || '@anon' + kw;
      scopes.push([name, parts, m[1], src.slice(brace, end + 1)]);
    }
    // Thin wrappers with no alias line at all - single-statement returns that delegate to
    // another composite (possibly binding the item mapper) or guard it against null.
    const thin = /function ([\w$]+)\((\w)\)\{return[^{}]{0,90}\}/g;
    for (let m; (m = thin.exec(src)); ) {
      scopes.push([m[1], [m[2]], null, 'DELEGATE ' + m[0]]);
    }
    // Inline composites: `function(s){return nl(s,$m)}(await ...)` - a member wraps a fetch
    // with an immediately-invoked composite that binds the item mapper. Same delegate
    // semantics, anonymous, so synthesized into a named delegate body.
    const iife = /function\((\w)\)\{return ([\w$]+)\(\1,\s*([\w$]+)\)\}\(/g;
    for (let m; (m = iife.exec(src)); ) {
      scopes.push(['@anon' + m.index, [m[1]], null, 'DELEGATE function x' + m.index + '(' + m[1] + '){return ' + m[2] + '(' + m[1] + ', ' + m[3] + ')}']);
    }
    const bare = new RegExp('function ([\\w$]+)\\((\\w)\\)\\{return \\w+\\[(?:' + AL + '|[\\w$]+)\\(\\d+\\)\\]\\(([' + '\\w$]+)\\)\\}', 'g');
    for (let m; (m = bare.exec(src)); ) {
      scopes.push([m[1], [m[2]], null, 'function ' + m[1] + '(' + m[2] + '){return LIST_OF[' + m[3] + ']}']);
    }
    return scopes;
  };

  const extractMappers = () => {
    const mappers = {};
    const delegates = {};
    const paramsOf = {};
    let total = 0;
    for (const [name, params, local, body] of extractScopes()) {
      paramsOf[name] = params;
      const arg = params[0];
      if (body.startsWith('DELEGATE ')) {
        delegates[name] = body.slice(9);
        continue;
      }
      if (local === null) {
        const child = /LIST_OF\[([\w$]+)\]/.exec(body)[1];
        mappers[name] = { inverse: false, listElement: child, entries: {} };
        continue;
      }
      const b = substitute(body, local);
      let inverse = false;
      let entries = null;
      const aliases = collectAliases(b, arg) || {};
      Object.assign(aliases, collectPrelude(b, arg, aliases));
      const mlit = /return\{/.exec(b);
      const mb = /(?:[,;]\s*|const\s+)(\w+)=\{\};return/.exec(b);
      if (mlit) {
        const objAt = b.indexOf('{', mlit.index + 'return'.length - 1);
        const litEnd = braceEnd(b, objAt);
        const lit = b.slice(objAt + 1, litEnd);
        const [parsed, spreads] = parseLiteralEntries(lit, arg, aliases);
        if (Object.keys(spreads).length) {
          const ordered = [];
          for (const pair of splitTop(lit)) {
            const pm = fullmatch('"([\\w$]+)":\\s*([\\s\\S]*)', 's', pair);
            if (pm) ordered.push([pm[1], parsed[pm[1]]]);
            else {
              const sm = fullmatch('\\{?\\.\\.\\.([\\w$]+)\\((\\w)\\)\\}?', 's', pair);
              if (sm) ordered.push(['spread:' + sm[1], null]);
            }
          }
          mappers[name] = { inverse, _ordered: ordered };
          continue;
        }
        entries = parsed;
      } else if (mb) {
        const temp = mb[1];
        const tail = b.slice(mb.index + mb[0].length);
        entries = {};
        for (const chunk of splitTop(tail)) {
          let piece = chunk.replace(new RegExp('^\\(?' + escapeRe(temp) + '\\.?'), '').trim();
          piece = piece.replace(/[;}]+$/, '').trim();
          if (!piece || piece === temp) continue;
          if (new RegExp('^' + escapeRe(temp) + '=\\{\\}$').test(piece)) continue;
          if (!piece.includes('=')) continue;
          const eq = piece.indexOf('=');
          const left = piece.slice(0, eq).trim();
          const right = piece.slice(eq + 1).trim();
          if (right.startsWith('{}')) continue;
          const qm = fullmatch('\\["[\'"]?([\\w$]+)["\'\']?\\]', '', left) || fullmatch('\\["([\\w$]+)"\\]', '', left);
          if (qm) {
            inverse = true;
            entries[qm[1]] = parseValue(right, arg, aliases);
          } else {
            entries[left] = parseValue(right, arg, aliases);
          }
        }
      } else {
        const av = /\((\w+)=>\(?\{([\s\S]*)\}\)?\)/.exec(b);
        if (av) {
          entries = parseLiteralEntries(av[2], av[1], aliases, arg)[0];
          const srcnames = Object.values(entries).filter((s) => s && s.k === 'prop').map((s) => s.n || '');
          const outkeys = Object.keys(entries);
          inverse = srcnames.length > 0 && srcnames.every((n) => n.length <= 3) && outkeys.every((k) => k.length >= 5);
        }
      }
      if (entries === null) continue;
      for (const k of Object.keys(entries)) if (!entries[k]) delete entries[k];
      total += Object.keys(entries).length;
      mappers[name] = { inverse, entries };
    }
    // post-pass: expand spreads into their parents
    const expand = (name, seen = []) => {
      const r = mappers[name];
      if (!r || !r._ordered) return r;
      if (seen.includes(name)) return null;
      const out = [];
      for (const [key, spec] of r._ordered) {
        if (key.startsWith('spread:')) {
          const sub = expand(key.slice(7), [...seen, name]);
          if (sub && sub.entries) out.push(...Object.entries(sub.entries));
        } else {
          out.push([key, spec]);
        }
      }
      r.entries = Object.fromEntries(out);
      delete r._ordered;
      return r;
    };
    for (const n of Object.keys(mappers)) expand(n);
    // post-pass: resolve thin delegates into real mappers
    //   T(v)              -> same entries as T
    //   v ? T(v) : null   -> same entries as T (null passes through the flatten)
    //   T(v, ITEM)        -> T's entries with T's second param bound to ITEM
    //   v[...](ITEM)      -> a list element: entries stay empty, listElement = ITEM
    const expandDelegate = (name, seen = []) => {
      if (mappers[name]) return mappers[name];
      const code = delegates[name];
      if (!code || seen.includes(name)) return null;
      seen = [...seen, name];
      let m = /^function [\w$]+\(\w\)\{return (\w)\?(\w+)\(\w\):null\}$/.exec(code);
      if (m) {
        const t = expandDelegate(m[2], seen);
        if (t && t.entries) {
          mappers[name] = { inverse: false, entries: JSON.parse(JSON.stringify(t.entries)) };
          return mappers[name];
        }
        return null;
      }
      m = /^function [\w$]+\(\w\)\{return ([\w$]+)\(\w,\s*([\w$]+)\)\}$/.exec(code);
      if (m) {
        const t = expandDelegate(m[1], seen);
        if (t && t.entries) {
          const bound = (paramsOf[m[1]] || [])[1];
          const entries = JSON.parse(JSON.stringify(t.entries));
          const rebind = (spec) => {
            if (!spec || typeof spec !== 'object') return;
            if (bound && spec.child === bound) spec.child = m[2];
            if (bound && spec.name === bound) spec.name = m[2];
            if (spec.entries) for (const s2 of Object.values(spec.entries)) rebind(s2);
          };
          for (const s of Object.values(entries)) rebind(s);
          mappers[name] = { inverse: false, entries };
          return mappers[name];
        }
        return null;
      }
      m = /^function [\w$]+\(\w\)\{return ([\w$]+)\(\w\)\}$/.exec(code);
      if (m) {
        const t = expandDelegate(m[1], seen);
        if (t && t.entries) {
          mappers[name] = { inverse: false, entries: JSON.parse(JSON.stringify(t.entries)) };
          return mappers[name];
        }
        return null;
      }
      m = /^function [\w$]+\(\w\)\{return \w\[[\s\S]{1,40}\]\((\w+)\)\}$/.exec(code);
      if (m && mappers[m[1]]) {
        mappers[name] = { inverse: false, listElement: m[1], entries: {} };
        return mappers[name];
      }
      return null;
    };
    for (const n of Object.keys(delegates)) expandDelegate(n);
    return { mappers, total };
  };

  // -------------------------------------------------------------- 3. roles

  const posDecode = () => {
    const pat = new RegExp('(' + AL + ')\\((\\d+)\\)', 'g');
    const rep = (all, alias, n) => {
      const s = decodeIdx(Number(n));
      const r = s !== null && identRe.test(s) && s.length + 2 <= all.length ? '"' + s + '"' : '_I(' + n + ')';
      return r.length <= all.length ? r.padEnd(all.length) : all;
    };
    // Length preservation matters here: composite wiring records '@anon' positions in this
    // text, and they must line up with source positions. Strvar substitution would shift
    // them, so it is deliberately not applied.
    return src.replace(pat, rep);
  };

  const valArgs = {};
  for (const [k, v] of Object.entries(table)) {
    if (typeof v === 'string' && !(v in valArgs)) valArgs[v] = Number(k);
  }
  const kindPat = (tokens) =>
    new RegExp(
      tokens
        .map((t) => (t in valArgs ? '(?:"' + escapeRe(t) + '"|_I\\(' + valArgs[t] + '\\))' : '"' + escapeRe(t) + '"'))
        .join('\\s*,\\s*'),
    );

  const resolveRoles = (mappers) => {
    const DSP = posDecode();
    const hasLastPage = (n) => n in mappers && Object.values(mappers[n].entries).some((v) => v && v.n === 'lastPage');

    const wireRole = (tokens) => {
      const kpat = kindPat(tokens);
      const tm = kpat.exec(DSP);
      if (!tm) return null;
      const segStart = Math.max(0, tm.index - 8000);
      const seg = DSP.slice(segStart, tm.index + tm[0].length + 400);
      let tab = null;
      for (const m of seg.matchAll(/(\w+)=(\{)/g)) {
        const off = m.index + m[1].length + 1 + segStart;
        const end = braceEnd(DSP, off);
        if (end >= tm.index) {
          tab = [m[1], DSP.slice(off, end)];
          break;
        }
      }
      if (!tab) return null;
      const [tabvar, tbody] = tab;
      let member = null;
      const marks = [...tbody.matchAll(/[(,{}](?:"([\w$]+)"|([\w$]+)):/g)];
      for (let i = 0; i < marks.length; i++) {
        const npos = i + 1 < marks.length ? marks[i + 1].index : tbody.length;
        if (kpat.test(tbody.slice(marks[i].index, npos))) {
          member = marks[i][1] || marks[i][2];
          break;
        }
      }
      if (!member) return null;
      const sb = new RegExp('\\.(\\w+)=' + escapeRe(tabvar) + '\\b').exec(src);
      if (!sb) return null;
      return [sb[1], member];
    };

    const compositeAfterConsumer = (svc, member) => {
      for (const cm of src.matchAll(new RegExp('\\.' + escapeRe(svc) + '\\.' + escapeRe(member) + '\\(', 'g'))) {
        const lo = Math.max(0, cm.index - 900);
        const cands = [];
        for (const am of DSP.slice(lo, cm.index + 900).matchAll(new RegExp('function\\((\\w)\\)\\{const ([\\w$]+)=(?:' + AL + ')[;,]', 'g'))) {
          const pos = lo + am.index;
          const aend = braceEnd(DSP, DSP.indexOf('{', pos));
          if (aend < 0) continue;
          const after = DSP.slice(aend, aend + 200).replace(/^}/, '');
          if (!/\(await \w+\.\w+\(/.test(after)) continue;
          if (new RegExp('\\.' + escapeRe(svc) + '\\.' + escapeRe(member) + '\\(').test(after.slice(0, 160))) {
            cands.push([Math.abs(pos - cm.index), pos]);
            continue;
          }
          const vam = /\(await \w+\.\w+\((\w+),/.exec(after);
          if (vam) {
            const v = vam[1];
            const pre = DSP.slice(Math.max(0, pos - 400), pos);
            if (new RegExp('\\b' + escapeRe(v) + '=\\w+\\.' + escapeRe(svc) + '\\.' + escapeRe(member) + '\\(').test(pre)) {
              cands.push([Math.abs(pos - cm.index), pos]);
            }
          }
        }
        if (cands.length) {
          cands.sort((a, b) => a[0] - b[0]);
          return '@anon' + cands[0][1];
        }
      }
      return null;
    };

    const namedCompositeConsumer = (svc, member) => {
      const cm = new RegExp('(\\w+)\\(await \\w+\\.\\w+\\(\\w+\\.' + escapeRe(svc) + '\\.' + escapeRe(member) + ',', 's').exec(DSP);
      return cm ? cm[1] : null;
    };

    const wired = {};
    for (const [tokens, slot] of [
      [['manga', 'list'], 'list'],
      [['manga', 'chapters'], 'chapters'],
      [['chapters', 'detail'], 'pages'],
    ]) {
      const w = wireRole(tokens);
      if (!w) continue;
      const [svc, member] = w;
      wired[slot] = slot === 'list' ? namedCompositeConsumer(svc, member) : compositeAfterConsumer(svc, member);
    }

    const shapeCands = {};
    for (const [n, r] of Object.entries(mappers)) {
      const es = r.entries;
      const lists = Object.values(es).filter((s) => s && s.k === 'list' && mappers[s.child] && !mappers[s.child].listElement);
      const metas = Object.values(es).filter((s) => s && s.k === 'child' && hasLastPage(s.name));
      if (lists.length && metas.length) (shapeCands.list = shapeCands.list || []).push(n);
    }
    for (const [n, r] of Object.entries(mappers)) {
      const es = r.entries;
      for (const s of Object.values(es)) {
        if (s && s.k === 'list') {
          const ch = mappers[s.child];
          if (ch && Object.values(ch.entries).some((v) => v && v.n === 'number') && Object.values(ch.entries).some((v) => v && v.n === 'name')) {
            const metas = Object.values(es).filter((s2) => s2 && s2.k === 'child' && hasLastPage(s2.name));
            if (metas.length) (shapeCands.chapters = shapeCands.chapters || []).push(n);
          }
        }
        if (s && s.k === 'child') {
          const c2 = mappers[s.name];
          if (c2 && Object.values(c2.entries).some((v) => v && v.k === 'concat')) {
            (shapeCands.pages = shapeCands.pages || []).push(n);
          }
        }
      }
    }

    const roles = {};
    const mismatch = [];
    for (const slot of ['list', 'chapters', 'pages']) {
      if (wired[slot] && wired[slot] in mappers) roles[slot] = wired[slot];
      else if (shapeCands[slot] && shapeCands[slot].length) roles[slot] = shapeCands[slot][0];
      if (wired[slot] && shapeCands[slot] && !shapeCands[slot].includes(wired[slot])) mismatch.push(slot);
    }
    if (mismatch.length || Object.keys(roles).length !== 3) {
      throw new Error('role resolution failed: wired=' + JSON.stringify(wired) + ' shapes=' + JSON.stringify(shapeCands));
    }
    return roles;
  };

  return { extractMappers, resolveRoles, posDecode, kindPat, valArgs };
}

/**
 * Runs the whole pipeline over a chunk's source and returns the registry object.
 * Throws loudly on anything it cannot fully resolve - a half-extracted registry must
 * never reach the oracle, which would either fail the sig check or serve wrong data.
 */
export function extractRegistry(chunkSrc) {
  const { table, decName, globalAlias, aliases } = recoverTable(chunkSrc);
  const { extractMappers, resolveRoles } = buildExtractor(chunkSrc, table, decName, globalAlias, aliases);
  const { mappers, total } = extractMappers();
  if (total < 100) throw new Error('implausibly few entries extracted: ' + total);
  const roles = resolveRoles(mappers);
  return { mappers, roles };
}

export { recoverTable, buildExtractor };

/** CLI: node heal.mjs <chunk-url-or-file> [out.json] */
if (process.argv[1] && process.argv[1].endsWith('heal.mjs')) {
  const target = process.argv[2];
  const out = process.argv[3];
  if (!target) {
    console.error('usage: node heal.mjs <chunk-url-or-file> [out.json]');
    process.exit(2);
  }
  const src = /^https?:/.test(target)
    ? await (await fetch(target)).text()
    : readFileSync(target, 'utf8');
  const registry = extractRegistry(src);
  const json = JSON.stringify(registry);
  if (out) {
    writeFileSync(out + '.tmp', json);
    renameSync(out + '.tmp', out);
  }
  console.log('mappers:', Object.keys(registry.mappers).length, 'roles:', JSON.stringify(registry.roles), 'bytes:', json.length);
}

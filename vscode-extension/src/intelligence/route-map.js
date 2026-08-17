'use strict';

/**
 * Endpoint → source mapping.
 *
 * DAST reports a URL; SAST reports a file and a line. Nothing links them unless
 * the route is actually declared somewhere in the source. This module reads the
 * route declarations that are really present in the workspace and refuses to
 * guess anything else: an unmapped endpoint stays unmapped.
 *
 * Supported declaration styles are limited to the ones Security Center can
 * recognise unambiguously today:
 *   - Express / Fastify / Koa-router:  app.get('/api/login', …)
 *   - Flask / FastAPI decorators:      @app.route('/api/login')  @app.post('/x')
 *   - Spring annotations:              @GetMapping("/api/login")
 * Anything else is reported as unsupported rather than approximated.
 */

const fs = require('fs/promises');
const path = require('path');

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all'];

// app.get('/x', …) / router.post("/x", …)
const JS_ROUTE = new RegExp(`\\b(?:app|router|server|fastify|api)\\s*\\.\\s*(${HTTP_METHODS.join('|')})\\s*\\(\\s*(['"\`])([^'"\`]+)\\2`, 'gi');
// @app.route('/x', methods=['POST']) / @router.post('/x')
const PY_ROUTE = new RegExp(`@\\s*\\w+\\s*\\.\\s*(route|${HTTP_METHODS.join('|')})\\s*\\(\\s*(['"])([^'"]+)\\2([^)]*)\\)`, 'gi');
// @GetMapping("/x") / @RequestMapping(value = "/x", method = RequestMethod.POST)
const JAVA_ROUTE = /@\s*(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"([^)]*)\)/gi;

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.java', '.kt']);
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', 'vendor', 'target', '__pycache__', '.venv']);

function normalizePath(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
}

/** `/api/users/:id` and `/api/users/{id}` both become `/api/users/*`. */
function routePattern(route) {
  const value = `/${String(route || '').trim().replace(/^\/+/, '').replace(/\/+$/, '')}`;
  return value
    .replace(/:[^/]+/g, '*')
    .replace(/\{[^}]*\}/g, '*')
    .replace(/<[^>]*>/g, '*')
    .toLowerCase() || '/';
}

/** Path part of a URL; a bare path is returned unchanged. */
function urlPath(endpoint) {
  const value = String(endpoint || '').trim();
  if (!value) return '';
  try { return new URL(value).pathname.toLowerCase(); } catch { /* not absolute */ }
  return value.split('?')[0].toLowerCase();
}

/**
 * Whether a concrete request path is served by a declared route pattern.
 * `*` matches exactly one segment, so `/api/users/*` never swallows
 * `/api/users/1/admin`.
 */
function pathMatchesRoute(requestPath, pattern) {
  const request = urlPath(requestPath).replace(/\/+$/, '') || '/';
  const route = String(pattern || '').replace(/\/+$/, '') || '/';
  if (request === route) return true;
  const requestSegments = request.split('/').filter(Boolean);
  const routeSegments = route.split('/').filter(Boolean);
  if (requestSegments.length !== routeSegments.length) return false;
  return routeSegments.every((segment, index) => segment === '*' || segment === requestSegments[index]);
}

function lineOfIndex(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

/** Route declarations contained in one source file. */
function extractRoutes(text, file) {
  const content = String(text || '');
  const relative = normalizePath(file);
  const routes = [];
  const push = (method, route, index, framework) => {
    const pattern = routePattern(route);
    if (!pattern.startsWith('/')) return;
    routes.push({
      file: relative,
      line: lineOfIndex(content, index),
      method: String(method || 'ANY').toUpperCase(),
      route: `/${String(route).replace(/^\/+/, '')}`,
      pattern,
      framework
    });
  };
  for (const match of content.matchAll(JS_ROUTE)) {
    push(match[1] === 'all' ? 'ANY' : match[1], match[3], match.index, 'express');
  }
  for (const match of content.matchAll(PY_ROUTE)) {
    const declared = match[1].toLowerCase();
    const methods = declared === 'route'
      ? (match[4]?.match(/['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]/gi) || []).map((value) => value.replace(/['"]/g, ''))
      : [declared];
    if (!methods.length) push('ANY', match[3], match.index, 'python');
    else for (const method of methods) push(method, match[3], match.index, 'python');
  }
  for (const match of content.matchAll(JAVA_ROUTE)) {
    const declared = match[1].toLowerCase();
    const method = declared === 'request'
      ? (match[3]?.match(/RequestMethod\.(GET|POST|PUT|PATCH|DELETE)/i)?.[1] || 'ANY')
      : declared;
    push(method, match[2], match.index, 'spring');
  }
  return routes;
}

async function* walkSourceFiles(root, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = await fs.readdir(root, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue;
      yield* walkSourceFiles(candidate, depth + 1);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      yield candidate;
    }
  }
}

/**
 * Scans the workspace once and returns every route it could recognise.
 * `frameworks` reports what was actually detected so the UI can say « aucune
 * route reconnue » instead of implying full framework coverage.
 */
async function buildRouteMap(workspacePath, { maxFiles = 800, maxFileSize = 1024 * 1024, readFile = fs.readFile } = {}) {
  const root = path.resolve(workspacePath);
  const routes = [];
  let scannedFiles = 0;
  for await (const file of walkSourceFiles(root)) {
    if (scannedFiles >= maxFiles) break;
    scannedFiles += 1;
    let text = '';
    try {
      const stat = await fs.stat(file);
      if (stat.size > maxFileSize) continue;
      text = await readFile(file, 'utf8');
    } catch { continue; }
    routes.push(...extractRoutes(text, path.relative(root, file)));
  }
  return {
    routes,
    scannedFiles,
    frameworks: [...new Set(routes.map((route) => route.framework))].sort(),
    supported: routes.length > 0
  };
}

/** Declared routes serving a request, most specific (fewest wildcards) first. */
function matchEndpoint(routeMap, endpoint, method = '') {
  const requested = String(method || '').toUpperCase();
  return (routeMap?.routes || [])
    .filter((route) => pathMatchesRoute(endpoint, route.pattern))
    .filter((route) => !requested || route.method === 'ANY' || route.method === requested)
    .sort((left, right) => (left.pattern.split('*').length - right.pattern.split('*').length));
}

module.exports = {
  HTTP_METHODS, routePattern, urlPath, pathMatchesRoute, extractRoutes,
  buildRouteMap, matchEndpoint, normalizePath
};

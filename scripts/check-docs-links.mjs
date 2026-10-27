// check-docs-links.mjs - checks internal links and anchors in the built docs site.
//
// Usage: node scripts/check-docs-links.mjs <dist-dir>
//
// Walks every *.html file under <dist-dir>, collects id="..." values and every
// href/src value, and verifies that internal links (under BASE) resolve to a
// file in the build and that #fragments exist in the target page. External
// links are not checked. Prints one line per problem and exits 1 if any,
// else prints "docs links: OK (...)" and exits 0.
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const BASE = "/peek/";
const SKIP = /^(http:|https:|mailto:|data:|javascript:|\/\/)/;

const dist = process.argv[2];
if (!dist) {
  console.error("usage: node scripts/check-docs-links.mjs <dist-dir>");
  process.exit(2);
}
const root = path.resolve(dist);

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else if (entry.name.endsWith(".html")) out.push(full);
  }
  return out;
}

async function isFile(p) {
  try {
    return (await stat(p)).isFile();
  } catch {
    return false;
  }
}

const decode = (v) => v.replaceAll("&amp;", "&");

const files = await walk(root);
const pages = new Map();
for (const file of files) {
  const html = await readFile(file, "utf8");
  const ids = new Set([...html.matchAll(/\sid="([^"]*)"/g)].map((m) => decode(m[1])));
  const links = [...html.matchAll(/\s(?:href|src)="([^"]*)"/g)].map((m) => decode(m[1]));
  pages.set(file, { ids, links });
}

// resolve maps a URL path (no fragment) onto a file in the build, or "".
async function resolve(urlPath, baseDir) {
  const rooted = urlPath.startsWith("/") ? path.join(root, urlPath) : path.resolve(baseDir, urlPath);
  if (!urlPath.endsWith("/") && (await isFile(rooted))) return rooted;
  const index = path.join(rooted, "index.html");
  return (await isFile(index)) ? index : "";
}

const problems = [];
let count = 0;
for (const [file, { ids, links }] of pages) {
  const rel = path.relative(root, file);
  for (const link of links) {
    if (link === "" || SKIP.test(link)) continue;
    count++;
    const fail = (reason) => problems.push(`${rel}: ${link}: ${reason}`);
    if (link.startsWith("#")) {
      if (!ids.has(link.slice(1))) fail("no such anchor in this page");
      continue;
    }
    const hash = link.indexOf("#");
    let target = hash < 0 ? link : link.slice(0, hash);
    const frag = hash < 0 ? "" : link.slice(hash + 1);
    if (target.startsWith(BASE)) {
      target = "/" + target.slice(BASE.length);
    } else if (target.startsWith("/")) {
      fail("absolute link outside /peek/");
      continue;
    }
    target = target.replace(/\?.*$/, "");
    const resolved = await resolve(target, path.dirname(file));
    if (!resolved) {
      fail("target not found");
      continue;
    }
    if (frag) {
      if (!resolved.endsWith(".html")) continue;
      const page = pages.get(resolved);
      if (!page || !page.ids.has(frag)) fail("no such anchor in target");
    }
  }
}

if (problems.length) {
  console.log(problems.join("\n"));
  process.exit(1);
}
console.log(`docs links: OK (${count} links in ${files.length} files)`);

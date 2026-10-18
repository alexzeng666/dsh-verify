// Rewrite local dependencies to concrete versions before publishing; publish.ps1 restores them from .bak afterwards.
//
// Why this is needed:
//   dsh-verify's dependencies are local paths like file:../dsh-quota (during a local install_bundle the
//   profile is not a workspace, so workspace:* cannot be resolved and file: is the only option).
//   npm pack / npm publish do **not** convert the file: protocol -- published as-is, installation fails
//   for everyone. dsh-timelab's workspace:* is the same story: pnpm substitutes it, npm does not.
//
// What it does:
//   1. file:../X and workspace:* in dependencies / peerDependencies -> ^<actual version of X>
//   2. remove devDependencies (only dsh-verify-contract, which is private and never published)
//
// Usage: node scripts/rewrite-deps.mjs [--check]
//   --check only inspects without writing, and exits with code 1 if anything is left over (used by publish.ps1's dry-run)
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packagesDir = join(root, 'packages');
const checkOnly = process.argv.includes('--check');

const dirs = readdirSync(packagesDir).filter((name) => statSync(join(packagesDir, name)).isDirectory());

/** package name -> version */
const versions = new Map();
for (const dir of dirs) {
  const manifest = JSON.parse(readFileSync(join(packagesDir, dir, 'package.json'), 'utf8'));
  versions.set(manifest.name, manifest.version);
}

const LOCAL_SPEC = /^(file:|link:|workspace:)/;

let problems = 0;

for (const dir of dirs) {
  const file = join(packagesDir, dir, 'package.json');
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  if (manifest.private === true) continue; // dsh-verify-contract: never published, leave untouched

  let changed = false;

  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = manifest[field];
    if (!deps) continue;
    for (const [name, spec] of Object.entries(deps)) {
      if (!LOCAL_SPEC.test(String(spec))) continue;
      const version = versions.get(name);
      if (!version) {
        console.error(`[!] ${manifest.name}: ${field}.${name} is a local dependency, but its version could not be found`);
        problems += 1;
        continue;
      }
      deps[name] = `^${version}`;
      changed = true;
    }
  }

  if (manifest.devDependencies) {
    delete manifest.devDependencies;
    changed = true;
  }

  if (!changed) continue;
  if (checkOnly) {
    console.error(`[!] ${manifest.name}: still has local dependencies that were not rewritten (run node scripts/rewrite-deps.mjs first)`);
    problems += 1;
    continue;
  }
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  console.log(`[+] ${manifest.name}: local dependencies rewritten to concrete versions, devDependencies removed`);
}

if (checkOnly) {
  if (problems > 0) process.exit(1);
  console.log('[ok] all packages have concrete versions in dependencies / peerDependencies');
}

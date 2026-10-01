import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const corbetSource = /^git\+https:\/\/github\.com\/corbet-(?:foss|libs)\//;

function checkSource(source, resolved) {
  const url = new URL(source.slice(4));
  const revision = url.searchParams.get('rev');
  const main = url.searchParams.toString() === 'branch=main';
  const pinned = [...url.searchParams.keys()].join() === 'rev'
    && /^[a-f0-9]{40}$/.test(revision ?? '');
  if ((!main && !pinned) || (resolved && (!/^#[a-f0-9]{40}$/.test(url.hash)
      || (pinned && url.hash !== `#${revision}`)))) {
    throw new Error(`Expected main or a matching transitive revision pin: ${source}`);
  }
}

export function checkPins(metadata) {
  const names = new Set(['crlt']);
  for (const pkg of metadata.packages) {
    if (corbetSource.test(pkg.source ?? '')) {
      names.add(pkg.name);
      checkSource(pkg.source, true);
    }
    // Inspect upstream selectors too; each repository enforces its own main declarations.
    for (const dependency of pkg.dependencies) {
      if (corbetSource.test(dependency.source ?? '')) {
        checkSource(dependency.source, false);
      }
    }
  }
  for (const name of names) {
    const packages = metadata.packages.filter(pkg => pkg.name === name);
    if (packages.length !== 1 || !corbetSource.test(packages[0].source ?? '')) {
      throw new Error(`Missing, unpinned or duplicated Corbet dependency: ${name}`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkPins(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  console.log('Corbet dependencies resolve once each to a complete source revision');
}

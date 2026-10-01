import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('./workflows/dependabot-auto-merge.yml', import.meta.url), 'utf8');
const script = source.split('          script: |\n')[1].split('\n').map(line => line.replace(/^            /, '')).join('\n');
const execute = new (Object.getPrototypeOf(async function () {}).constructor)('github', 'context', script);
const names = ["resolve", "check", "dependency-policy", "coverage"];
const head = 'a'.repeat(40);
const goodPr = { number: 1, user: { login: 'dependabot[bot]' }, state: 'open', draft: false,
  base: { ref: 'main' }, head: { sha: head, repo: { full_name: 'example/stack' } } };

function fixture(overrides = {}) {
  let reads = 0;
  const merges = [];
  const calls = [];
  const run = { id: 10, workflow_id: 20, path: '.github/workflows/ci.yml', head_sha: head, pull_requests: [{ number: 1 }], ...overrides.run };
  const branch = { protected: true, protection: { required_status_checks: { enforcement_level: 'everyone', contexts: names } }, ...overrides.branch };
  const jobs = overrides.jobs ?? names.map(name => ({ name, status: 'completed', conclusion: 'success' }));
  const checks = overrides.checks ?? names.map(name => ({ name, status: 'completed', conclusion: 'success', app: { slug: 'github-actions' } }));
  const github = {
    paginate: async method => method(),
    rest: {
      actions: { getWorkflow: async () => ({ data: { id: 20 } }), listJobsForWorkflowRun: async () => jobs },
      repos: { listPullRequestsAssociatedWithCommit: async () => overrides.associated ?? [{ number: 1 }], getBranch: async () => ({ data: branch }), getCombinedStatusForRef: async () => ({ data: overrides.status ?? { total_count: 0 } }) },
      checks: { listForRef: async () => checks },
      pulls: {
        get: async () => ({ data: reads++ ? (overrides.latest ?? overrides.pr ?? goodPr) : (overrides.pr ?? goodPr) }),
        merge: async params => { merges.push(params); return { data: { merged: overrides.merged ?? true } }; }
      }
    }
  };
  // No checkout, workflow dispatch, artifact download or GraphQL privilege exists.
  return { merges, calls, run: () => execute(github, { repo: { owner: 'example', repo: 'stack' }, payload: { workflow_run: run } }) };
}

test('green exact head uses the protected REST endpoint with an atomic SHA', async () => {
  const f = fixture(); await f.run();
  assert.deepEqual(f.merges, [{ owner: 'example', repo: 'stack', pull_number: 1, sha: head, merge_method: 'squash' }]);
});
for (const [name, override] of [
  ['wrong workflow', { run: { workflow_id: 21 } }],
  ['wrong path', { run: { path: '.github/workflows/untrusted.yml' } }],
  ['missing coverage', { jobs: names.filter(name => name !== 'coverage').map(name => ({ name, status: 'completed', conclusion: 'success' })) }],
  ['skipped check', { jobs: names.map(name => ({ name, status: 'completed', conclusion: name === 'coverage' ? 'skipped' : 'success' })) }],
  ['unprotected branch', { branch: { protected: false } }],
  ['administrator bypass', { branch: { protection: { required_status_checks: { enforcement_level: 'non_admins', contexts: names } } } }],
  ['missing protected coverage', { branch: { protection: { required_status_checks: { enforcement_level: 'everyone', contexts: names.filter(name => name !== 'coverage') } } } }],
  ['untrusted check app', { checks: names.map(name => ({ name, status: 'completed', conclusion: 'success', app: { slug: 'other' } })) }],
  ['failing status', { status: { total_count: 1, state: 'failure' } }]
]) test(name, async () => {
  const f = fixture(override); await assert.rejects(f.run()); assert.equal(f.merges.length, 0);
});
for (const [name, override] of [
  ['human author', { pr: { ...goodPr, user: { login: 'contributor' } } }],
  ['fork', { pr: { ...goodPr, head: { ...goodPr.head, repo: { full_name: 'other/stack' } } } }],
  ['draft', { pr: { ...goodPr, draft: true } }],
  ['stale run', { pr: { ...goodPr, head: { ...goodPr.head, sha: 'b'.repeat(40) } } }],
  ['head moves after checks', { latest: { ...goodPr, head: { ...goodPr.head, sha: 'b'.repeat(40) } } }],
  ['base changes after checks', { latest: { ...goodPr, base: { ref: 'other' } } }]
]) test(name, async () => {
  const f = fixture(override); await f.run(); assert.equal(f.merges.length, 0);
});
test('server refusal remains an error with no bypass attempt', async () => {
  const f = fixture({ merged: false }); await assert.rejects(f.run()); assert.equal(f.merges.length, 1);
});

test('empty workflow association uses commit-associated pull requests', async () => {
  const f = fixture({ run: { pull_requests: [] } }); await f.run();
  assert.equal(f.merges.length, 1); assert.equal(f.merges[0].sha, head);
});
test('missing workflow and commit associations fail visibly', async () => {
  const f = fixture({ run: { pull_requests: [] }, associated: [] });
  await assert.rejects(f.run()); assert.equal(f.merges.length, 0);
});

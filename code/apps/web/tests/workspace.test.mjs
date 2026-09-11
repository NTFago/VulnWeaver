import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregatePipelineStages, pipelineProgress } from '../src/lib/pipeline.ts';
import { findingCounts, pseudocodeText, reportView } from '../src/lib/report-view.ts';
const job = (id, kind, status, extra = {}) => ({ id, kind, status, updated_at: '2026-09-11T00:00:00Z', failure: null, ...extra });
const task = { status: 'analyzing' };
const project = { exploit_validation_enabled: true };
const stage = (jobs, key, context = task, config = project) => aggregatePipelineStages(jobs, 'source', context, config).find(s => s.key === key);
test('each binary analysis job contributes once, even with repeated delivery', () => {
  const one = job('j1', 'binary_analysis', 'succeeded');
  const stages = aggregatePipelineStages([one, one], 'binary', task, project);
  assert.equal(stages.flatMap(s => s.jobs).length, 1);
  assert.deepEqual(pipelineProgress(stages), { settled: 1, total: 1, succeeded: 1, failed: 0, percent: 100, activeNames: [] });
});
test('permission waiting is distinct from running and queued', () => {
  assert.equal(stage([job('j', 'proof', 'waiting_permission')], 'verify').status, 'waiting_permission');
  assert.equal(stage([job('j', 'proof', 'queued')], 'verify').status, 'queued');
});
test('an absent source fuzz job is not evidence that fuzz is disabled', () => {
  assert.equal(stage([], 'fuzz').status, 'pending');
  assert.equal(stage([], 'fuzz', task, { exploit_validation_enabled: false }).status, 'skipped');
  assert.equal(stage([], 'fuzz', { status: 'completed' }).status, 'not_scheduled');
  assert.equal(stage([job('j', 'fuzz', 'running')], 'fuzz', task, { exploit_validation_enabled: false }).status, 'running');
});
test('partial failures remain visible while job completion reaches 100%', () => {
  const jobs = [job('a', 'review', 'succeeded'), job('b', 'review', 'failed', { failure: { code: 'review.failed', message: 'timeout' } })];
  assert.equal(stage(jobs, 'review').status, 'partial');
  assert.match(stage(jobs, 'review').failureText, /timeout/);
  const progress = pipelineProgress(aggregatePipelineStages(jobs, 'source', { status: 'completed' }, project));
  assert.equal(progress.percent, 100);
  assert.equal(progress.failed, 1);
  assert.equal(progress.succeeded, 1);
});
test('additional scheduled work changes execution denominator without fake coverage', () => {
  const jobs = [job('a', 'import', 'succeeded'), job('b', 'semantic_audit', 'queued')];
  assert.equal(pipelineProgress(aggregatePipelineStages(jobs, 'source')).percent, 50);
  assert.equal(pipelineProgress(aggregatePipelineStages([], 'source')).percent, 0);
});
test('a cancelled stage is not reported as successful', () => {
  assert.equal(stage([job('j', 'report', 'cancelled')], 'report').status, 'cancelled');
});
test('report formats keep independent states and old artifacts after another failure', () => {
  const jobs = [job('a', 'report', 'failed', { arguments: { format: 'pdf' } }), job('b', 'report', 'waiting_permission', { arguments: { format: 'sarif' } })];
  const versions = [{ id: 'pdf-old', generation_config: { format: 'pdf' } }];
  assert.equal(reportView('pdf', jobs, versions).versions[0].id, 'pdf-old');
  assert.equal(reportView('pdf', jobs, versions).active, false);
  assert.equal(reportView('sarif', jobs, versions).active, true);
  assert.equal(reportView('markdown', jobs, versions).jobs.length, 0);
});
test('Ghidra list, legacy string and malformed pseudo code are handled without invented text', () => {
  assert.equal(pseudocodeText({ attributes: { pseudocode: [{ text: 'int main() {}' }, null, { text: 9 }, { text: 'return 0;' }] } }), 'int main() {}\n\nreturn 0;');
  assert.equal(pseudocodeText({ attributes: { pseudocode: 'legacy()' } }), 'legacy()');
  assert.equal(pseudocodeText({ attributes: { pseudocode: [{ text: {} }] } }), null);
});
test('false positives do not raise active severity or confirmed counts', () => {
  const counts = findingCounts([{ severity: 'critical', status: 'false_positive' }, { severity: 'high', status: 'candidate' }, { severity: 'low', status: 'confirmed' }]);
  assert.equal(counts.total, 3); assert.equal(counts.active.length, 2); assert.equal(counts.confirmed, 1); assert.equal(counts.pending, 1); assert.equal(counts.falsePositive, 1);
});

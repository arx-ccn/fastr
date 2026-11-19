// bun --no-env-file tests/bench/mailbox.ts FILE SEED ws://127.0.0.1:PORT fastr|magnitude
// FILE comes from Magnitude's relay-bench gen. Only fixture keys sign AUTH.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { once } from 'node:events';

const [file, seed, url, relay] = Bun.argv.slice(2);
assert(['fastr', 'magnitude'].includes(relay) && new URL(url).hostname === '127.0.0.1');
function le(n: bigint) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n);
  return buf;
}

type Event = {
  id: string;
  pubkey: string;
  sig: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};
function newestFirst(a: Event, b: Event) {
  return b.created_at - a.created_at || (a.id < b.id ? -1 : Number(a.id !== b.id));
}
const clients = Array.from({ length: 8 }, (_, i) => {
  const key = createHash('sha256')
    .update(le(BigInt(seed)))
    .update('recipient')
    .update(le(BigInt(i)))
    .digest('hex');
  const pub = Bun.spawnSync(['nak', 'key', 'public', key]);
  assert.equal(pub.exitCode, 0);
  return { key, pk: pub.stdout.toString().trim(), events: [] as Event[] };
});
const boxes = new Map(clients.map((c) => [c.pk, c.events]));
for await (const line of createInterface({ input: createReadStream(file) })) {
  const ev: Event = JSON.parse(line);
  if (ev.kind === 1059) {
    for (const [name, value] of ev.tags) {
      if (name === 'p') {
        boxes.get(value)?.push(ev);
      }
    }
  }
}
for (const c of clients) {
  c.events.sort(newestFirst);
  assert(c.events.length >= 100, `fixture mailbox ${c.pk} has fewer than 100 wraps`);
}

// One outstanding REQ per socket. Include JSON decoding, stop latency at EOSE,
// and check every field and the tie order before issuing another request.
for (const workload of ['id', 'ids_100', 'inbox_500']) {
  const samples: number[] = [];
  let events = 0;
  const sessions = await Promise.all(
    clients.map(async ({ key, pk, events: box }) => {
      const ws = new WebSocket(url);
      const frames: unknown[][] = [];
      let notify: (() => void) | undefined;
      ws.onmessage = (e) => {
        frames.push(JSON.parse(e.data));
        notify?.();
      };
      async function receive() {
        if (frames.length === 0) {
          const { promise, resolve, reject } = Promise.withResolvers<void>();
          const timeout = setTimeout(() => reject(Error('relay reply timed out')), 10000);
          notify = resolve;
          try {
            await promise;
          } finally {
            clearTimeout(timeout);
            notify = undefined;
          }
        }
        return frames.shift()!;
      }
      await once(ws, 'open');
      assert.equal(ws.extensions, '', 'disable WebSocket compression on both relays');
      if (relay === 'fastr') {
        const [type, challenge] = await receive();
        assert.equal(type, 'AUTH');
        const auth = Bun.spawnSync([
          'nak',
          'event',
          '--sec',
          key,
          '-k',
          '22242',
          '-c',
          '',
          '-t',
          `relay=${url}`,
          '-t',
          `challenge=${challenge}`,
        ]);
        assert.equal(auth.exitCode, 0);
        const signed = JSON.parse(auth.stdout.toString());
        ws.send(JSON.stringify(['AUTH', signed]));
        assert.deepEqual((await receive()).slice(0, 3), ['OK', signed.id, true]);
      }
      async function query(i: number) {
        const start = (i * 97) % box.length;
        const expected =
          workload === 'inbox_500'
            ? box.slice(0, 500)
            : Array.from(
                { length: workload === 'id' ? 1 : 100 },
                (_, j) => box[(start + j) % box.length],
              ).sort(newestFirst);
        const filter =
          workload === 'inbox_500'
            ? { kinds: [1059], '#p': [pk], limit: 500 }
            : { ids: expected.map((e) => e.id), limit: expected.length };
        const sub = String(i),
          req = JSON.stringify(['REQ', sub, filter]);
        const got: unknown[] = [];
        const t = performance.now();
        ws.send(req);
        for (;;) {
          const [type, id, ev] = await receive();
          assert.equal(id, sub);
          if (type === 'EOSE') {
            break;
          }
          assert.equal(type, 'EVENT');
          got.push(ev);
        }
        const elapsed = performance.now() - t;
        ws.send(JSON.stringify(['CLOSE', sub]));
        assert.deepEqual(got, expected);
        if (i > 0) {
          samples.push(elapsed);
          events += got.length;
        }
      }
      return { query, ws };
    }),
  );
  await Promise.all(sessions.map((s) => s.query(0)));
  const queries = workload === 'id' ? 4000 : 100;
  const start = performance.now();
  await Promise.all(
    sessions.map(async (s) => {
      for (let i = 1; i <= queries; i++) {
        await s.query(i);
      }
    }),
  );
  const seconds = (performance.now() - start) / 1000;
  sessions.forEach((s) => s.ws.close());
  samples.sort((a, b) => a - b);
  const percentile = (p: number) => samples[Math.ceil(samples.length * p) - 1];
  console.log(
    JSON.stringify({
      relay,
      workload,
      requests: samples.length,
      events,
      qps: samples.length / seconds,
      p50_ms: percentile(0.5),
      p99_ms: percentile(0.99),
    }),
  );
}

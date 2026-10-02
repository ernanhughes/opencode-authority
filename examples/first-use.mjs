const emit = value => console.log(JSON.stringify(value, null, 2));
import { readFileSync } from 'node:fs';
import { AuthorityCheck, AuthorityHealth } from '../src/tools.ts';
const policy = JSON.parse(readFileSync(new URL('./policy.json', import.meta.url), 'utf8'));
const proposal = {
  proposal_id: 'first-search', purpose: 'book-travel',
  external_operation: { kind: 'ACT', action: 'search-flights' },
  data_uses: [{ source: { id: 'calendar:travel-window', kind: 'calendar' },
    operation: 'ACCESS', necessary: true }],
};
const input = { proposal, policy };
emit(input);
emit(JSON.parse((await AuthorityHealth().execute({}, undefined)).content));
emit(JSON.parse((await AuthorityCheck().execute(input, undefined)).content));

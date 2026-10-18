# dsh-verify-contract

Shared types for the dsh-verify suite. **Private — not published.**

## What is in it

`src/index.d.ts` holds four declarations and no runtime code:

```ts
export type FragmentSource = 'quota' | 'crashlab' | 'probe' | 'timelab' | 'orchestrator';
export interface VerifyFragment { /* what every package reports */ }
export interface TimelineEntry  { /* cross-package correlation */ }
export declare const TOOL_PREFIX: 'verify_';
```

## Usage

Type-only:

```ts
import type { VerifyFragment } from '@alexzeng666/dsh-verify-contract';
```

Runtime value imports fail — there is no `.js` in the package.

## Why it is a separate package

Packages couple through this contract and nothing else, so adding a package needs no changes
elsewhere and each one still builds on its own. Each package lists it under `devDependencies`;
`scripts/rewrite-deps.mjs` drops that block before publishing, so it never reaches a published
manifest.

+++
title = "Zcash Zebra GHSA-8gxx-hc65-vv82 writeup"
# date = "2026-09-28"
# latest
date = "2026-10-08"

#
# description is optional
#
# description = "An optional description for SEO. If not provided, an automatically created summary will be used."

+++

In July, I reported a chain-stall vulnerability in [Zebra](https://github.com/ZcashFoundation/zebra), a widely used [Zcash](https://z.cash) node client — [GHSA-8gxx-hc65-vv82](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-8gxx-hc65-vv82). In this article, I explain the root cause and the patch.

## Summary

In Zebra, if a block fails contextual validation, its hash is recorded in `parent_error_map`. When the block write task receives a new block, Zebra rejects it if its parent hash is in `parent_error_map`. An entry in the map isn't evicted until the size of the map exceeds `PARENT_ERROR_MAP_LIMIT` (= 2,000) because no other code path removes entries from the map.

Using the same primitive as in [GHSA-4m69-67m6-prqp](https://github.com/advisories/GHSA-4m69-67m6-prqp), an attacker can build a block that has the same hash as a fully valid block but fails contextual validation (aka a poisoned block). Then the attacker can propagate the poisoned block to a victim node before it receives the valid block with the same hash.

As a result, the block hash is recorded in `parent_error_map`, and child blocks can't be committed until that hash is evicted from the map. Under normal circumstances, it takes roughly 2,000 valid blocks (~41 hours) to evict that hash, and the victim node remains stuck at a specific height during that time.

## Description

### 1. GHSA-4m69-67m6-prqp primitive

According to ZIP-244, a v5 transaction's `auth_digest` (which commits to `scriptSig`) isn't used to calculate its `txid`. The block header's `hashMerkleRoot` is calculated using only the `txid` of each transaction, so it doesn't commit to `auth_digest`. Instead, `hashBlockCommitments` commits to `auth_digest`.

Zebra validates blocks in two stages, semantic validation and contextual validation. During semantic validation, Zebra checks `hashMerkleRoot` but not `hashBlockCommitments`. Validating `hashBlockCommitments` requires chain history data, so Zebra checks it during contextual validation.

Therefore, an attacker can build a block with the same hash as a fully valid block by mutating the coinbase transaction's `scriptSig`. The mutated block (aka a poisoned block) passes semantic validation but fails contextual validation. It fails the `block_commitment_is_valid_for_chain_history` check during `validate_and_commit_non_finalized`.

### 2. `parent_error_map` entry eviction logic

1. If a block fails validation in `validate_and_commit_non_finalized`, its hash is recorded in `parent_error_map` (`write.rs#L409`).
2. If a block's parent hash is in `parent_error_map`, the block is also rejected (`write.rs#L393-L394`).
3. An entry is evicted from `parent_error_map` only when the map size exceeds `PARENT_ERROR_MAP_LIMIT` (= 2,000) (`write.rs#L412-L415`).

```rust
// zebra-state/src/service/write.rs#L392-L415 (15d57836)
            let result = if let Some(parent_error) = parent_error {
                Err(parent_error.clone())
            } else {
                tracing::trace!(?child_hash, "validating queued child");
                validate_and_commit_non_finalized(
                    &finalized_state.db,
                    non_finalized_state,
                    queued_child,
                )
            };

            // TODO: fix the test timing bugs that require the result to be sent
            //       after `update_latest_chain_channels()`,
            //       and send the result on rsp_tx here

            if let Err(ref error) = result {
                // If the block is invalid, mark any descendant blocks as rejected.
                parent_error_map.insert(child_hash, error.clone());

                // Make sure the error map doesn't get too big.
                if parent_error_map.len() > PARENT_ERROR_MAP_LIMIT {
                    // We only add one hash at a time, so we only need to remove one extra here.
                    parent_error_map.shift_remove_index(0);
                }
```

## Patch

In PR [#10995](https://github.com/ZcashFoundation/zebra/pull/10995), the Zebra team added code that removes a block's entry from `parent_error_map` once the block is successfully committed.

Interesting point: I think the GHSA-4m69 PoC may still have worked until GHSA-8gxx was patched.

## Reflection

This is my first vulnerability report, so I was really excited while finding and reporting this bug. I'm going to keep looking for vulnerabilities in blockchain nodes because node clients are more complex and have more attack surfaces than smart contracts. I hope my efforts will help make Web3 more secure.

## References

1. [https://zips.z.cash/zip-0244](https://zips.z.cash/zip-0244)
2. [https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-8gxx-hc65-vv82](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-8gxx-hc65-vv82)
3. [https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-4m69-67m6-prqp](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-4m69-67m6-prqp)
4. [https://github.com/ZcashFoundation/zebra/pull/10995](https://github.com/ZcashFoundation/zebra/pull/10995)
5. [https://github.com/zcash/zcash/security/advisories/GHSA-rpcw-q5mr-gq35](https://github.com/zcash/zcash/security/advisories/GHSA-rpcw-q5mr-gq35)

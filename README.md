# grant

**Who may do what, decided as pure data.** This repository is the capability
broker for the Kotoba stack: it normalises a manifest, resolves a policy,
admits or refuses a component, and returns a capability *specification*. It
never turns that specification into a runtime handle, never opens a socket,
and never executes anything.

It came out of [`kotoba-lang/aiueos`](https://github.com/kotoba-lang/aiueos)
on 2026-08-21 (root ADR-2608219500). Aiueos kept the machine; this kept the
decision.

```clojure
(require '[grant.broker :as broker]
         '[grant.policy :as policy]
         '[grant.manifest :as manifest])
```

## Why it is separate

`aiueos` named two things at once — the authority that decides which hand to
lend, and the operating system that lends it. Both were real and both were
growing, and measured at the split they were nearly the same size: about 6,400
lines of decision against about 6,100 lines of mechanism plus 7,000 lines of C
and assembly. One repository cannot be dependency-minimal and own a kernel.

The dependency direction is one-way and checkable: **aiueos depends on grant,
grant does not depend on aiueos.** At the split the require graph had zero
edges from the decision plane into the machine, so the cut needed no
rewriting to make it hold — it was already true and simply unstated.

## What is here

| Namespace | Decides |
|---|---|
| `grant.authority` | the Principal–Intent–Decision kernel: `:allow` / `:deny` / `:challenge` |
| `grant.causal-trust` | scoped evaluator claims → trust challenge → ordinary authority decision and secret-free receipt |
| `grant.broker` | grant/deny per component, the ADR-0004 admission gate, run-plan and run-receipt shaping |
| `grant.policy` | the policy reasoner: signers, forbidden effects, ABAC, surface conformance |
| `grant.contract` | the pure EDN contract every other namespace here validates against |
| `grant.manifest` | trust / limits / quota / schedule / topic defaults |
| `grant.graph` | the capability graph, boot order, dependency depth |
| `grant.surface` | the deployment-surface and provider registry |
| `grant.signing` | ed25519 manifest verification (verification only; key custody is not here) |
| `grant.publisher` `grant.update` `grant.ota` `grant.anchors` `grant.enroll` `grant.key-lifecycle` | the decision half of release, update, pairing and signer lifecycle |
| `grant.boot-admission` `grant.deployment-profile` `grant.native-effect` | may these artifacts boot, under which profile, with which effects |
| `grant.cloud` `grant.net` `grant.kagi-policy` | may this component reach that remote authority, that URL, that secret reference |
| `grant.audit` `grant.clock` `grant.cli` `grant.decide` `grant.component-abi` `grant.execution-decision` | the append-only record, trusted time, the CLI contract, and the bridges into all of it |

## What is deliberately not here

- **No Wasm engine, and no engine dependency of any kind.** `aiueos.execute`
  and its Chicory dependency stayed with the machine. Deciding whether a
  component may run is not the same act as running it, and a decision plane
  behind an engine cannot be audited without one.
- **No credential parsing.** `grant.authority` accepts verified, data-only
  facts. Cookies, CACAO, Passkeys, JWTs and private keys are adapter concerns.
- **No key custody.** `grant.signing` verifies; it does not sign.
- **No hardware.** PCI, DMA, IRQ and MMIO are aiueos.

## One covering relation

`grant.authority` still accepts its stable `[action resource]` EDN contract,
but it now projects each value into an unambiguous `authority.scope` segment
and delegates covering to
[`kotoba-lang/authority`](https://github.com/kotoba-lang/authority). Exact
resources and the legacy `:*` resource wildcard therefore use the same partial
order as the rest of the fleet. EDN type tags come from `pr-str`; path-shaping
characters are escaped before a value becomes one segment, so prefix confusion
cannot be reintroduced by string coercion.

## Contract data keeps its `aiueos` vocabulary

The EDN under `resources/aiueos/` and every `:aiueos.policy/*`,
`:aiueos.broker/*` and `:aiueos/*` key is unchanged, and so are the classpath
paths that load them. Those keys are on the wire — `kototama`'s adapter, the
example manifests, and every stored decision read them. Renaming code is cheap
and renaming a vocabulary is not, so only the namespaces moved. The same call
was made when the pin registry became genpon and `:fleet/repos` stayed
(ADR-2608147300).

Three contract entries still name files that now live in the other repository
(`src/aiueos/vm.cljc`, `src/aiueos/pid1.cljc`, `src/aiueos/provider/cloud.clj`,
under `:enforced-by`, `:read-at-boot-by` and `:consumed-by`). Nothing checks
those paths for existence, which is exactly why they are named here.

## Verify

```bash
clojure -M:test
```

291 tests, 918 assertions at the split.

Three tests stayed in `aiueos` because they reach into the machine:
`manifest_test` (needs `aiueos.execute`), `key_lifecycle_test` (needs
`aiueos.launcher`) and `deployment_profile_test` (needs
`aiueos.reproducibility`), plus `example_fixtures_test`, which reads the
`examples/` tree where each `.edn` is paired with the `.wat` it describes.
`grant.manifest`, `grant.key-lifecycle` and `grant.deployment-profile`
therefore ship here without an in-repository test.

## License

Apache-2.0.

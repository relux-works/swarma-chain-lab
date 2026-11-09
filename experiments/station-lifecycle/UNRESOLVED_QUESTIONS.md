# External inputs and unverified behavior

- This candidate intentionally binds r2 with the safe pending rule. Wall-clock
  freshness in proposed r3 cannot prove permanent absence across a backward
  clock step. A follow-up must bind the stable r4 CLOCK_BOOTTIME + boot_id fence,
  with restart/reboot and delayed-processing controls. Do not mix this codec
  with a helper requiring the later request fields or claim deployment readiness.
- The Infra-owned swarma-slotd-demo implementation and root policy must receive
  their own exact-head review and Linux controls. This client binds protocol v1 r2
  (hash in README); no real helper, user, systemd unit, nftables rule or VM was
  exercised by the macOS controls. Cross-compilation is not runtime verification.
- Operator inputs: disjoint numeric ranges, fixed payload/hash, root helper
  socket/caller admission, private state directories, manager mTLS identity,
  gateway/client leaf pins and trust roots. No new privileges are installed here.
- The actual rented agent/runtime, Curator profile, model access proxy and budgets
  remain product/deployment decisions. The private bootstrap v1 carries only
  booking identity, station name and channel credential. Its gateway address and
  TLS pin are separately operator-pinned payload inputs. A scripted fixture is
  not a real rented agent.
- GW1 owns the serve listener and bounded inbound worker. Integrate the signed
  adapter head there, then independently validate the resulting exact head.
- A helper failed state or absence after an uncertain Start attempt needs operator
  reconciliation. Protocol r2 cannot fence a delayed Create using status=absent.
  The adapter requires a matching destroyed record after any Start attempt.
  A helper failed state needs operator reconciliation. Do not reset journals or
  recycle a retained number to bypass it. A manager journal byte limit can bind
  before the 64-record limit when bootstrap documents are large.
- Replace this demo adapter when platform user-manager / curator-run lifecycle
  ships; relay changes must not pull gateway/a2a types into the core slot API.

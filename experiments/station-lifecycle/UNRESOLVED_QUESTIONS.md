# External inputs and unverified behavior

- This candidate binds stable r4 CLOCK_BOOTTIME + boot_id. Actual helper
  interoperability and Linux boot-clock execution remain external validation.
  No r2/r3 fallback or timestamp regeneration is provided. Legacy r2 attempts
  without a durable fence remain pending until matching destroyed evidence.
- The Infra-owned swarma-slotd-demo implementation and root policy must receive
  their own exact-head review and Linux controls. This client binds protocol v1 r4
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
- A helper failed state or unfenced legacy attempt needs operator reconciliation.
  Do not reset journals or recycle a retained number to bypass it. A manager
  journal byte limit can bind before 64 records when bootstrap documents are large.
- Replace this demo adapter when platform user-manager / curator-run lifecycle
  ships; relay changes must not pull gateway/a2a types into the core slot API.

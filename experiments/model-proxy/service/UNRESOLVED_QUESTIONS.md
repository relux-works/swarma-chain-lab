# Integration inputs

1. The assigned base has the older flat deploy-kit release builder, not the
   named A3 per-product release template or set-fragment contract. Supply the
   accepted A3 template/revision before extending its artifact inventory. The
   existing release contract is not silently replaced or reinterpreted.
2. A runnable gateway service is not supplied by this module. The existing
   model-proxy daemon's managed-mode brokerSource marker is package-private;
   this module cannot implement it while remaining separate and importing no
   other experiment. Identify the runtime integration owner and accepted CLI
   before treating the install template as an installable gateway artifact.
3. A production protected launch/authority/matcher provider and listener
   custody implementation, final submission/response fences and restart
   reconciliation are not qualified by fixture tests. Missing evidence stays
   closed; no permissive production guard is provided.

These are delivery/integration gates, not claims of contradictory broker wire
semantics. No alternative provider, exposed-mode fallback or secret input is
introduced to compensate for them.

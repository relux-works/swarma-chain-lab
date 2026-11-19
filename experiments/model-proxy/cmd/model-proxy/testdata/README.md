# Claude Code intake structure fixture

`claude-code-2.1.328-messages.json` combines the measured OAuth beta header
profile with a structural reconstruction of the client request. The supplied
PR review traces the exact 2.1.328 bundle's `Xne({scope, ttl})`, `Iii` static
system-block placement and `yOs` cache-control mapping. The fixture records
those keys and types: text system blocks, exact global cache scope, optional
TTL, client-executed tools and message text blocks. All text, tool names,
schemas and model identifiers are synthetic. It is not a captured client body,
a live-client replay, or evidence that every client request form is supported.

The `anthropic_beta` member supplies the HTTP header, not a Messages body field.
`TestGatewayComposedClaudeCodeCacheScope` sends the nested `body` through the
production Unix listener, broker holder, meter and pinned TLS transport. Its
plain/global/global-with-TTL controls preserve request bytes and the beta header;
unknown scope values, aliases and members refuse without consuming the valid
control's reservation. Unit tests independently check exact prices and the
ceiling-minus-one boundary.

# Public LIP-0006 vectors

These are synthetic public fixtures, not live requests or authorization. The
grantee uses public test scalar 2; the service uses public test scalar 7. Never
use either for funds. Wire JSON files have no trailing newline. Literal bytes
and standard SHA256/BIP340 produced the vectors independently of product codecs.

- Request SHA256: `f3fb78db4d8324dfc4537b2822c51ae9c44c3554d82ef30666b5779a6aab7763`.
- Action digest: `fe5351a4aef1ba65173f49dc6d828f83e5bdddd02cd917520df1f4fef4ef9e10`.
- Receipt public key: `5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc`.
- Receipt digest: `90a94a1cf305f07bb595ae073597baa45c295d34de4a89112af6eeee38049d72`.

`TestActionGolden` checks exact request bytes, both domains, both signatures and
rejection of an action signed over the ASCII hash instead of its binary bytes.
The empty effect is an encoding vector, not a claim about a live balance result.

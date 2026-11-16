package chaingateway

import "slices"

// Evidence is internal and assembled only after the corresponding kernel,
// namespace, dump and protected-node checks. It is never read from wire/config.
type platformEvidence struct {
	platform                                   string
	endpoint, dump, user, network, bind, allow bool
}

func exclusiveNode(c Configuration) bool {
	return c.AllowedUIDs != nil && c.WorkloadUIDs != nil && c.NodeDedicated &&
		!slices.Contains([]uint32{0, 65534, 65535, 4294967295}, c.NodeUID) &&
		c.NodeUID != c.ServerUID && !slices.Contains(c.AllowedUIDs, c.NodeUID) && !slices.Contains(c.WorkloadUIDs, c.NodeUID)
}
func admitCredentialHolder(c Configuration, e platformEvidence) error {
	if e.platform != "linux" || !e.endpoint || !e.dump || !e.user || !e.network || !e.bind || !e.allow || !exclusiveNode(c) {
		return bad("credential-holder proof")
	}
	return nil
}

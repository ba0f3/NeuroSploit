package types

type ReconPolicy string

const (
	ReconPolicyAsk   ReconPolicy = "ask"   // TTY prompt when bundle found
	ReconPolicyNew   ReconPolicy = "new"   // force fresh bootstrap
	ReconPolicyReuse ReconPolicy = "reuse" // force import; error if missing
)

const DefaultReconCachePath = "data/recon-cache"

package version

// Version is overridden at build time via -ldflags "-X ssh-fleet/internal/version.Version=vX.Y.Z".
var Version = "dev"

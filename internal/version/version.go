package version

// Version is the Vectis release version. Set at build time via
// -ldflags "-X github.com/Veltara-Works/vectis/internal/version.Version=vX.Y.Z".
// Defaults to "dev" for unversioned local builds.
var Version = "dev"

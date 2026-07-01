package engagement

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// ApplyCreds loads creds.yaml into cfg: auth header, host SSH/AD instructions, auto-login.
func ApplyCreds(ctx context.Context, cfg *types.RunConfig, path string) error {
	if path == "" {
		return nil
	}
	cr := creds.Load(path)
	if cr == nil {
		fmt.Fprintf(os.Stderr, "  [!] no usable credentials in %s\n", path)
		return nil
	}
	fmt.Fprintf(os.Stderr, "  [*] loaded credentials from %s\n", path)

	if cfg.Auth == nil {
		cfg.Auth = cr.AuthHeader()
	}
	if hi := cr.HostInstruction(); hi != nil {
		prependInstructions(cfg, *hi)
		fmt.Fprintf(os.Stderr, "  [*] host credentials loaded (SSH/Windows-AD)\n")
	}
	if cfg.Auth != nil {
		return nil
	}
	if cr.Login == nil {
		return nil
	}
	login := cr.Login
	fmt.Fprintf(os.Stderr, "  [*] auto-login: %s %s ...\n", login.Method, login.URL)
	auth, note, err := creds.DoLogin(ctx, login)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] auto-login failed (%v); agents will attempt to log in themselves\n", err)
		if li := cr.LoginInstruction(); li != nil {
			prependInstructions(cfg, *li)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "  [*] authenticated — %s\n", note)
	cfg.Auth = &auth
	return nil
}

func prependInstructions(cfg *types.RunConfig, block string) {
	block = strings.TrimSpace(block)
	if block == "" {
		return
	}
	if cfg.Instructions == nil || strings.TrimSpace(*cfg.Instructions) == "" {
		cfg.Instructions = &block
		return
	}
	merged := block + "\n" + strings.TrimSpace(*cfg.Instructions)
	cfg.Instructions = &merged
}

package cli

import (
	"fmt"
	"strings"
	"time"
)

// --- provisioner ---

const provisionerUsage = "usage: peek provisioner create --name <name> | peek provisioner list | peek provisioner revoke <id>"

func cmdProvisioner(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", provisionerUsage)
	}

	var run func(*client) error
	switch args[0] {
	case "create":
		var name string
		for i := 1; i < len(args); i++ {
			switch {
			case args[i] == "--name":
				if i+1 >= len(args) {
					return fmt.Errorf("--name requires a value")
				}
				name = args[i+1]
				i++
			case strings.HasPrefix(args[i], "-"):
				return fmt.Errorf("unknown flag: %s", args[i])
			default:
				return fmt.Errorf("unexpected argument: %s", args[i])
			}
		}
		if name == "" {
			return fmt.Errorf("--name is required")
		}
		run = func(c *client) error {
			var out struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
				Key  string `json:"key"`
			}
			if err := c.postJSON("/api/provisioners", map[string]string{"name": name}, &out); err != nil {
				return err
			}
			fmt.Printf("created provisioning key for %q (id %d):\n  %s\nStore it now; Peek does not show it again.\n", out.Name, out.ID, out.Key)
			return nil
		}
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("%s", provisionerUsage)
		}
		run = func(c *client) error {
			var out []struct {
				ID         int64  `json:"id"`
				Name       string `json:"name"`
				LastUsedAt int64  `json:"last_used_at"`
				Accounts   int64  `json:"accounts"`
			}
			if err := c.getJSON("/api/provisioners", &out); err != nil {
				return err
			}
			fmt.Printf("%-5s  %-8s  %-20s  %s\n", "ID", "ACCOUNTS", "LAST USED", "NAME")
			for _, p := range out {
				last := "never"
				if p.LastUsedAt > 0 {
					last = time.Unix(p.LastUsedAt, 0).UTC().Format(time.RFC3339)
				}
				fmt.Printf("%-5d  %-8d  %-20s  %s\n", p.ID, p.Accounts, last, truncate(p.Name, 40))
			}
			return nil
		}
	case "revoke":
		if len(args) != 2 || strings.HasPrefix(args[1], "-") {
			return fmt.Errorf("%s", provisionerUsage)
		}
		idSeg, err := tokenIDPath(args[1])
		if err != nil {
			return err
		}
		run = func(c *client) error {
			if err := c.del("/api/provisioners/"+idSeg, nil); err != nil {
				return err
			}
			fmt.Printf("revoked provisioner %s\n", idSeg)
			return nil
		}
	default:
		return fmt.Errorf("unknown provisioner subcommand: %s", args[0])
	}

	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	return run(c)
}

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type grantArgs struct {
	slug  string
	email string
	kind  string
}

func parseGrantArgs(name string, args []string) (grantArgs, error) {
	g := grantArgs{kind: "user"}
	var pos []string
	for _, a := range args {
		switch {
		case a == "--group":
			g.kind = "group"
		case strings.HasPrefix(a, "-"):
			return g, fmt.Errorf("unknown flag: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		return g, fmt.Errorf("usage: peek %s <slug> <email> [--group]", name)
	}
	g.slug, g.email = pos[0], pos[1]
	return g, nil
}

func cmdGrant(args []string) error {
	g, err := parseGrantArgs("grant", args)
	if err != nil {
		return err
	}
	seg, err := slugPath(g.slug)
	if err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	in := map[string]string{"kind": g.kind, "email": g.email}
	if err := c.postJSON("/api/uploads/"+seg+"/grants", in, nil); err != nil {
		return err
	}
	fmt.Printf("granted %s %s on %s\n", g.kind, g.email, g.slug)
	return nil
}

func cmdRevoke(args []string) error {
	g, err := parseGrantArgs("revoke", args)
	if err != nil {
		return err
	}
	seg, err := slugPath(g.slug)
	if err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	b, err := json.Marshal(map[string]string{"kind": g.kind, "email": g.email})
	if err != nil {
		return err
	}
	resp, err := c.req("DELETE", "/api/uploads/"+seg+"/grants", strings.NewReader(string(b)), "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := decodeResp(resp, nil); err != nil {
		return err
	}
	fmt.Printf("revoked %s %s on %s\n", g.kind, g.email, g.slug)
	return nil
}

func cmdGrants(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: peek grants <slug>")
	}
	seg, err := slugPath(args[0])
	if err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	var items []struct {
		Kind      string `json:"kind"`
		Email     string `json:"email"`
		CreatedAt int64  `json:"created_at"`
	}
	if err := c.getJSON("/api/uploads/"+seg+"/grants", &items); err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no grants")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", it.Kind, it.Email, time.Unix(it.CreatedAt, 0).Format(time.RFC3339))
	}
	return tw.Flush()
}

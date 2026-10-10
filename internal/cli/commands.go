package cli

import (
	"fmt"
	"os"

	"github.com/andras-tkcs/peek/internal/version"
)

// Run dispatches a command. args is argv without the program name.
func Run(args []string) int {
	if len(args) == 0 {
		usage()
		return 1
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "login":
		err = cmdLogin(rest)
	case "config":
		err = cmdConfig(rest)
	case "upload":
		err = cmdUpload(rest)
	case "list":
		err = cmdList(rest)
	case "delete":
		err = cmdDelete(rest)
	case "visibility":
		err = cmdVisibility(rest)
	case "rename":
		err = cmdRename(rest)
	case "grant":
		err = cmdGrant(rest)
	case "revoke":
		err = cmdRevoke(rest)
	case "grants":
		err = cmdGrants(rest)
	case "versions":
		err = cmdVersions(rest)
	case "stats":
		err = cmdStats(rest)
	case "comments":
		err = cmdComments(rest)
	case "export":
		err = cmdExport(rest)
	case "delete-all":
		err = cmdDeleteAll(rest)
	case "token":
		err = cmdToken(rest)
	case "help", "-h", "--help":
		usage()
		return 0
	case "version", "-v", "--version":
		fmt.Println("peek " + version.String())
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `peek — Peek CLI

Usage:
  peek login [--host <url>]             sign in with browser login when available
  peek login --token-stdin              read an access token from stdin
  peek config set --host <url>          set host (use 'login' / --token-stdin for the token)
  peek config show
  peek upload <file.html> --password <pw> [--name <filename>]
  peek upload <file.html> --password-stdin
  peek upload <file.html> --visibility public|private
  peek upload <file.html> --visibility restricted
  peek upload <file.html> --slug <slug>        upload a new version of an existing page
  peek list
  peek delete <slug>
  peek visibility <slug> public
  peek visibility <slug> private
  peek visibility <slug> restricted
  peek visibility <slug> password --password <pw>
  peek visibility <slug> password --password-stdin
  peek rename <slug> <new name>        rename a page; its link follows the name and old links redirect
  peek grant <slug> <email> [--group]  give a user (or Google group) access to a restricted page
  peek revoke <slug> <email> [--group] remove a grant
  peek grants <slug>                   list grants on a page
  peek stats <slug>
  peek versions <slug>                 list versions of one of your pages
  peek comments <slug> [--version <n>]  list comments (latest version by default)
  peek export <slug>                   export all data for an upload
  peek delete-all                      delete all your uploads
  peek token create --name <name>      create a new user token (admin only)
  peek token list                      list tokens (admin only)
  peek token revoke <id>               revoke a token by id (admin only)

Token input (most secure first):
  peek login                           browser login when available; otherwise hidden prompt
  peek login --token-stdin             read token from a pipe
  peek login --token-file <path>       read token from a file
  peek login --token <token>           discouraged: exposed in history & 'ps'
  PEEK_TOKEN=…  (env override)          handy for CI
  peek config set --token-stdin        read token from a pipe
  peek config set --token-file <path>  read token from a file
  peek config set --token <token>      discouraged: exposed in history & 'ps'

Environment overrides:
  PEEK_HOST, PEEK_TOKEN
`)
}

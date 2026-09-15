package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hirotomasato/autoclawpi/internal/client"
	"github.com/hirotomasato/autoclawpi/internal/db"
)

func cmdAccount(args []string) error {
	if len(args) == 0 {
		return listAccounts()
	}
	switch args[0] {
	case "list", "ls":
		return listAccounts()
	case "add":
		return addAccount(args[1:])
	case "remove", "rm", "delete":
		return removeAccount(args[1:])
	case "show":
		return showAccount(args[1:])
	case "disable":
		return setAccountsActive(args[1:], false)
	case "enable":
		return setAccountsActive(args[1:], true)
	case "disable-agent-access":
		return disableAgentAccessAccounts(args[1:])
	default:
		return fmt.Errorf("subcommand: list | add | remove | show | disable <id>... | enable <id>... | disable-agent-access")
	}
}

func listAccounts() error {
	accounts, err := db.ListAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		fmt.Println("tidak ada akun. jalankan 'autoclawpi login' atau 'autoclawpi import'")
		return nil
	}
	fmt.Printf("%-4s %-20s %-8s %-12s %-8s %-4s %-24s %s\n", "ID", "Name", "Provider", "User", "Points", "On", "Token Source", "Last Used")
	for _, a := range accounts {
		active := "✓"
		if !a.Active {
			active = "✗"
		}
		fmt.Printf("%-4d %-20s %-8s %-12s %-8d %-4s %-24s %s\n", a.ID, truncate(a.Name, 18), a.Provider, truncate(a.UserName, 10), a.Points, active, tokenSourceLabel(a.AccessToken), truncate(a.LastUsedAt, 16))
	}
	return nil
}

func addAccount(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	name := fs.String("name", "", "nama akun")
	access := fs.String("access", "", "access token")
	refresh := fs.String("refresh", "", "refresh token (opsional)")
	provider := fs.String("provider", "zai", "zai | google")
	allowAgent := fs.Bool("allow-agent-access", false, "izinkan token bersumber agent-access (selalu ditolak upstream)")
	fs.Parse(args)

	if *access == "" {
		fmt.Fprintf(os.Stderr, "usage: autoclawpi account add --access <token> [--refresh <token>] [--name <name>] [--provider zai|google]\n")
		os.Exit(2)
	}
	// Token bersumber agent-access selalu ditolak upstream dengan 410004,
	// jadi menambahkannya hanya menghasilkan akun mati. Arahkan ke OAuth.
	if !*allowAgent && client.IsAgentAccessToken(*access) {
		return fmt.Errorf("token bersumber agent-access (source_id=%s) selalu ditolak upstream dengan 410004; "+
			"login lewat OAuth di web panel dengan akun Google asli, atau pakai --allow-agent-access untuk memaksa",
			client.SourceAgentAccess)
	}
	deviceID := fmt.Sprintf("autoclawpi-%d", time.Now().UnixNano())
	id, err := db.AddAccount(*name, *access, *refresh, *provider, "", "", deviceID)
	if err != nil {
		return err
	}
	fmt.Printf("akun #%d ditambahkan (source_id=%s)\n", id, tokenSourceLabel(*access))
	return nil
}

// tokenSourceLabel mengembalikan source_id token untuk ditampilkan ke user.
func tokenSourceLabel(token string) string {
	if src := client.TokenSource(token); src != "" {
		return src
	}
	return "tidak terbaca"
}

// setAccountsActive mengaktifkan/menonaktifkan akun berdasarkan ID.
// Menonaktifkan bersifat reversibel (pakai `enable`), bukan menghapus.
func setAccountsActive(ids []string, active bool) error {
	if len(ids) == 0 {
		verb := "disable"
		if active {
			verb = "enable"
		}
		return fmt.Errorf("usage: autoclawpi account %s <id> [id...]", verb)
	}
	action := "dinonaktifkan"
	if active {
		action = "diaktifkan"
	}
	for _, raw := range ids {
		var id int64
		if _, err := fmt.Sscanf(raw, "%d", &id); err != nil || id <= 0 {
			return fmt.Errorf("id %q tidak valid", raw)
		}
		a, err := db.GetAccount(id)
		if err != nil {
			return err
		}
		if a == nil {
			return fmt.Errorf("akun #%d tidak ditemukan", id)
		}
		if err := db.SetAccountActive(id, active); err != nil {
			return err
		}
		fmt.Printf("akun #%d (%s) %s\n", id, a.Name, action)
	}
	return nil
}

// disableAgentAccessAccounts menonaktifkan semua akun yang tokennya bersumber
// agent-access. Token jenis itu selalu ditolak upstream dengan 410004, jadi
// akun seperti itu tidak akan pernah bisa melayani inference.
//
// Nonaktif (bukan hapus) supaya token aslinya tetap tersimpan dan bisa
// diaktifkan lagi lewat `account enable <id>`.
func disableAgentAccessAccounts(args []string) error {
	fs := flag.NewFlagSet("disable-agent-access", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "hanya tampilkan, tidak mengubah apa pun")
	fs.Parse(args)

	accounts, err := db.ListAccounts()
	if err != nil {
		return err
	}

	var targets []db.Account
	for _, a := range accounts {
		if a.Active && client.IsAgentAccessToken(a.AccessToken) {
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		fmt.Println("tidak ada akun aktif bersumber agent-access")
		return nil
	}

	for _, a := range targets {
		if *dryRun {
			fmt.Printf("akan dinonaktifkan: #%d (%s)\n", a.ID, a.Name)
			continue
		}
		if err := db.SetAccountActive(a.ID, false); err != nil {
			return err
		}
		fmt.Printf("akun #%d (%s) dinonaktifkan\n", a.ID, a.Name)
	}

	if *dryRun {
		fmt.Printf("\n%d akun akan dinonaktifkan (dry-run, belum ada perubahan)\n", len(targets))
		return nil
	}
	fmt.Printf("\n%d akun dinonaktifkan. Token tetap tersimpan; dùng `account enable <id>` để hoàn tác.\n", len(targets))
	fmt.Println("Thêm account OAuth thật qua web panel để bắt đầu dùng được inference.")
	return nil
}

func removeAccount(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: autoclawpi account remove <id>")
	}
	var id int64
	if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
		return fmt.Errorf("id harus angka")
	}
	if err := db.DeleteAccount(id); err != nil {
		return err
	}
	fmt.Printf("akun #%d dihapus\n", id)
	return nil
}

func showAccount(args []string) error {
	var id int64
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &id)
	}
	var a *db.Account
	var err error
	if id > 0 {
		a, err = db.GetAccount(id)
	} else {
		a, err = db.GetActiveAccount()
	}
	if err != nil {
		return err
	}
	if a == nil {
		return fmt.Errorf("akun tidak ditemukan")
	}

	// fetch saldo real-time dari server
	_, cl := loadAll()
	balance, _ := fetchBalance(cl, a.AccessToken)
	if balance > 0 {
		db.UpdatePoints(a.ID, balance) // update total
		a.Points = balance             // refresh local struct
	}

	fmt.Printf("ID        : %d\n", a.ID)
	fmt.Printf("Name      : %s\n", a.Name)
	fmt.Printf("Provider  : %s\n", a.Provider)
	fmt.Printf("UserID    : %s\n", a.UserID)
	fmt.Printf("UserName  : %s\n", a.UserName)
	fmt.Printf("DeviceID  : %s\n", a.DeviceID)
	fmt.Printf("Points    : %d pts (server: %d)\n", a.Points, balance)
	fmt.Printf("Active    : %v\n", a.Active)
	fmt.Printf("Created   : %s\n", a.CreatedAt)
	fmt.Printf("LastUsed  : %s\n", a.LastUsedAt)
	fmt.Printf("Access    : %s... (len=%d)\n", redactToken(a.AccessToken), len(a.AccessToken))
	fmt.Printf("Refresh   : %s... (len=%d)\n", redactToken(a.RefreshToken), len(a.RefreshToken))
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func redactToken(s string) string {
	if s == "" {
		return "(kosong)"
	}
	if len(s) > 20 {
		return s[:20]
	}
	return s
}

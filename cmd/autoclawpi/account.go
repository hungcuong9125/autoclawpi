package main

import (
	"context"
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
	case "check":
		return checkAccounts(args[1:])
	default:
		return fmt.Errorf("subcommand: list | add | remove | show | check | disable <id>... | enable <id>... | disable-agent-access")
	}
}

// checkAccounts menanyakan status tiap akun ke /userapi/v1/user-profile.
//
// Jauh lebih murah dan lebih pasti daripada menembak endpoint inference lalu
// menebak dari kode galatnya: endpoint ini menyebut statusnya terus terang
// ("User banned" untuk 410004).
func checkAccounts(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	all := fs.Bool("all", false, "periksa semua akun, termasuk yang nonaktif")
	fs.Parse(args)

	accounts, err := db.ListAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		fmt.Println("tidak ada akun")
		return nil
	}

	var targets []db.Account
	if len(fs.Args()) > 0 {
		for _, raw := range fs.Args() {
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
			targets = append(targets, *a)
		}
	} else {
		for _, a := range accounts {
			if *all || a.Active {
				targets = append(targets, a)
			}
		}
	}

	_, cl := loadAll()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	banned := 0
	for _, a := range targets {
		st, err := cl.UserProfile(ctx, a.AccessToken)
		switch {
		case err != nil:
			fmt.Printf("  #%-3d %-18s ERROR   %v\n", a.ID, truncate(a.Name, 16), err)
		case st.Banned():
			banned++
			fmt.Printf("  #%-3d %-18s BANNED  (code=%d %s)\n", a.ID, truncate(a.Name, 16), st.Code, st.Msg)
		case st.Code == 0:
			fmt.Printf("  #%-3d %-18s OK\n", a.ID, truncate(a.Name, 16))
		default:
			fmt.Printf("  #%-3d %-18s ERROR   code=%d %s\n", a.ID, truncate(a.Name, 16), st.Code, st.Msg)
		}
	}

	fmt.Println()
	if banned > 0 {
		fmt.Printf("%d/%d akun banned by AutoClaw (410004). This is server-side account status — "+
			"a new token, refresh, or re-login cannot recover it. Use a different account.\n", banned, len(targets))
	} else {
		fmt.Printf("%d akun checked, none banned.\n", len(targets))
	}
	return nil
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
	fs.Parse(args)

	if *access == "" {
		fmt.Fprintf(os.Stderr, "usage: autoclawpi account add --access <token> [--refresh <token>] [--name <name>] [--provider zai|google]\n")
		os.Exit(2)
	}
	// source_id hanya dicatat untuk diagnostik. Jangan menolak token
	// berdasarkan nilainya — pengukuran menunjukkan source_id tidak
	// menentukan apakah token diterima upstream.
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
// agent-access (source_id=agentaccess_token).
//
// Catatan: source_id TIDAK menentukan apakah akun ditolak upstream — perintah
// ini hanya alat bersih-bersih untuk akun yang sudah diketahui mati, bukan
// penyaring otomatis. Nonaktif (bukan hapus) supaya token aslinya tetap
// tersimpan dan bisa diaktifkan lagi lewat `account enable <id>`.
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
	fmt.Printf("\n%d akun dinonaktifkan. Token tetap tersimpan; use `account enable <id>` to undo.\n", len(targets))
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

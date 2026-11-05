package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/orcinustools/bima"
)

// skillMeta reads name/description from a SKILL.md front matter.
func skillMeta(name string) (desc string) {
	f, err := bima.Assets.Open(path.Join("skills", name, "SKILL.md"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "description:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func skillNames() []string {
	entries, _ := fs.ReadDir(bima.Assets, "skills")
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func defaultSkillsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".claude/skills"
	}
	return filepath.Join(home, ".claude", "skills")
}

func cmdSkills(args []string) int {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list":
		for _, n := range skillNames() {
			fmt.Printf("%s\n  %s\n", n, skillMeta(n))
		}
		return 0

	case "show":
		name, file := "bima-setup", "SKILL.md"
		if len(args) > 0 {
			name = args[0]
		}
		if len(args) > 1 {
			file = args[1]
		}
		b, err := fs.ReadFile(bima.Assets, path.Join("skills", name, path.Clean("/" + file)[1:]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "no such skill file %s/%s\nfiles:\n", name, file)
			_ = fs.WalkDir(bima.Assets, path.Join("skills", name), func(p string, d fs.DirEntry, _ error) error {
				if d != nil && !d.IsDir() {
					fmt.Fprintln(os.Stderr, "  "+strings.TrimPrefix(p, "skills/"+name+"/"))
				}
				return nil
			})
			return 1
		}
		os.Stdout.Write(b)
		return 0

	case "install":
		f := flag.NewFlagSet("skills install", flag.ExitOnError)
		dir := f.String("dir", defaultSkillsDir(), "skills directory of your agent (Claude Code: ~/.claude/skills or <project>/.claude/skills)")
		force := f.Bool("force", false, "overwrite an existing installation")
		_ = f.Parse(args)
		names := f.Args()
		if len(names) == 0 {
			names = skillNames()
		}
		for _, n := range names {
			dst := filepath.Join(*dir, n)
			if _, err := os.Stat(dst); err == nil && !*force {
				fmt.Fprintf(os.Stderr, "%s already exists (use --force to overwrite)\n", dst)
				return 1
			}
			src := path.Join("skills", n)
			if _, err := fs.Stat(bima.Assets, src); err != nil {
				fmt.Fprintf(os.Stderr, "unknown skill %q\n", n)
				return 1
			}
			err := fs.WalkDir(bima.Assets, src, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				target := filepath.Join(dst, filepath.FromSlash(strings.TrimPrefix(p, src)))
				if d.IsDir() {
					return os.MkdirAll(target, 0o755)
				}
				b, err := fs.ReadFile(bima.Assets, p)
				if err != nil {
					return err
				}
				return os.WriteFile(target, b, 0o644)
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "install:", err)
				return 1
			}
			fmt.Printf("installed skill %s → %s\n", n, dst)
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "usage: bima skills list | show [NAME [FILE]] | install [--dir DIR] [--force] [NAME...]\n")
	return 2
}

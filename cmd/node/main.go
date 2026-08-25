package main

import (
	"flag"
	"log"
	"trn/internal"
)

func main() {
	configPath := flag.String("config", "configs/node.yaml", "config file")
	flag.Parse()
	cfg, err := internal.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	node := internal.NewUniversalNode(cfg)
	if err := node.Start(); err != nil {
		log.Fatalf("node start: %v", err)
	}
	select {} // бесконечное ожидание
}

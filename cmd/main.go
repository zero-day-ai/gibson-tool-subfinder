package main

import (
	"log"
	"time"

	"github.com/zero-day-ai/sdk/serve"
	subfinder "github.com/zero-day-ai/gibson-tool-subfinder"
)

func main() {
	tool := subfinder.NewTool()
	if err := serve.Tool(tool,
		serve.WithPlatformFromEnv(),
		serve.WithGracefulShutdown(30*time.Second),
	); err != nil {
		log.Fatal(err)
	}
}

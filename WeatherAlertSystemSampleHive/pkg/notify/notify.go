// SPDX-License-Identifier: Apache-2.0

// Package notify provides the alert notification dispatcher cell.
package notify

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/model"
)

// Cell is the Hive cell for the notification dispatcher.
var Cell = cell.Module(
	"notify",
	"Alert notification dispatcher",

	cell.Config(Config{
		Channel:   "console",
		Recipient: "admin@example.com",
	}),
	cell.Provide(NewNotifier),
)

// Config holds notifier configuration.
type Config struct {
	Channel   string `mapstructure:"notify-channel"`
	Recipient string `mapstructure:"notify-recipient"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.String("notify-channel", c.Channel, "Notification channel: console or email")
	flags.String("notify-recipient", c.Recipient, "Email recipient for alerts")
}

// Notifier dispatches alerts to configured channels.
type Notifier struct {
	cfg Config
	log *slog.Logger
	mu  sync.Mutex

	lastAlert time.Time
	total     int
}

type params struct {
	cell.In

	Log    *slog.Logger
	Config Config
}

// New creates a Notifier instance.
func NewNotifier(p params) *Notifier {
	p.Log.Info("Notifier initialized",
		"channel", p.Config.Channel,
		"recipient", p.Config.Recipient)
	return &Notifier{
		cfg: p.Config,
		log: p.Log,
	}
}

// Send dispatches an alert through the configured channel.
func (n *Notifier) Send(alert model.Alert) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Simple dedup: don't send more than 1 alert per 5 seconds
	if time.Since(n.lastAlert) < 5*time.Second {
		return
	}
	n.lastAlert = time.Now()
	n.total++

	switch n.cfg.Channel {
	case "console":
		fmt.Printf("\n")
		fmt.Printf("  ╔════════════════════════════════════════════════════════╗\n")
		fmt.Printf("  ║  🚨 ALERT #%d [%s]                                   \n", n.total, alert.Severity)
		fmt.Printf("  ║  %s\n", alert.Message)
		fmt.Printf("  ║  Location: %s | Time: %s\n",
			alert.Reading.Location,
			alert.Reading.Timestamp.Format("15:04:05"))
		fmt.Printf("  ╚════════════════════════════════════════════════════════╝\n")
		fmt.Printf("\n")
	case "email":
		n.log.Info("Sending email alert",
			"to", n.cfg.Recipient,
			"severity", alert.Severity,
			"message", alert.Message)
	}
}

package wrapper

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.postgres_ssl",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// UnmarshalCaddyfile sets up the listener Listenerwrapper from Caddyfile tokens. Syntax:
//
//	postgres_ssl {
//		timeout <duration>
//		allow <IPs...>
//		deny <IPs...>
//	}
func (w *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// No same-line options are supported
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing postgres_ssl timeout duration: %v", err)
			}
			w.Timeout = caddy.Duration(dur)

		case "allow":
			w.Allow = append(w.Allow, d.RemainingArgs()...)
		case "deny":
			w.Deny = append(w.Deny, d.RemainingArgs()...)
		default:
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Module          = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

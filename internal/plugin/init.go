package plugin

import (
	"ai-sec-check/internal/gologger"
)

func RegisterAllPlugins(cfg func(name string) PluginConfig) error {
	plugins := []ScannerPlugin{
		NewInfraGuardPlugin(),
		NewSensitiveWordPlugin(),
		NewMcpSecPlugin(),
		NewGarakPlugin(),
		NewAutoswaggerPlugin(),
		NewRatelimitPlugin(),
	}

	for _, p := range plugins {
		pluginCfg := cfg(p.Name())
		if !pluginCfg.GetBool("enabled") {
			gologger.Infof("Plugin %s is disabled, skipping", p.Name())
			continue
		}
		if err := p.Init(pluginCfg); err != nil {
			gologger.Errorf("Failed to initialize plugin %s: %v", p.Name(), err)
			continue
		}
		if err := Register(p); err != nil {
			gologger.Errorf("Failed to register plugin %s: %v", p.Name(), err)
			continue
		}
		available := "available"
		if !p.IsAvailable() {
			available = "unavailable"
		}
		gologger.Infof("Plugin registered: %s [%s] (%s)", p.Name(), p.Category(), available)
	}

	return nil
}

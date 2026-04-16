package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage SkillGuard configuration",
	Long:  `View or modify SkillGuard configuration. Config is stored in ~/.skillguard.yaml`,
}

var configPath string
var configThreshold int

var showConfigCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE:  showConfig,
}

var setConfigCmd = &cobra.Command{
	Use:   "set",
	Short: "Set configuration value",
	RunE:  setConfig,
}

func init() {
	configCmd.AddCommand(showConfigCmd)
	configCmd.AddCommand(setConfigCmd)

	setConfigCmd.Flags().StringVarP(&configPath, "path", "p", "",
		"Default scan path")
	setConfigCmd.Flags().IntVarP(&configThreshold, "threshold", "t", 0,
		"Default threshold (0-100)")

	rootCmd.AddCommand(configCmd)
}

func showConfig(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	fmt.Println("SkillGuard Configuration")
	fmt.Println("=======================")
	fmt.Printf("Default path: %s\n", cfg.DefaultPath)
	fmt.Printf("Threshold:    %d\n", cfg.Threshold)
	fmt.Printf("Config file:  %s\n", viper.ConfigFileUsed())
	return nil
}

func setConfig(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()

	if configPath != "" {
		cfg.DefaultPath = configPath
	}
	if configThreshold > 0 {
		cfg.Threshold = configThreshold
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Configuration updated. Run 'skillguard config show' to verify.\n")
	return nil
}

type Config struct {
	viper       *viper.Viper
	DefaultPath string `mapstructure:"default_path"`
	Threshold   int    `mapstructure:"threshold"`
}

func loadConfig() *Config {
	v := viper.New()
	v.SetConfigName("skillguard")
	v.SetConfigType("yaml")
	v.AddConfigPath("$HOME")
	v.AddConfigPath(".")

	v.SetDefault("default_path", "~/.agents/skills")
	v.SetDefault("threshold", 70)

	v.ReadInConfig()

	return &Config{viper: v}
}

func (c *Config) Save() error {
	c.viper.Set("default_path", c.DefaultPath)
	c.viper.Set("threshold", c.Threshold)
	return c.viper.SafeWriteConfig()
}

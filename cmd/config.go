package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	// configName is the viper config name; the file on disk is
	// ~/.skillguard.yaml, the location documented in the README.
	configName       = ".skillguard"
	defaultThreshold = 70
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

	location := cfg.path
	if cfg.viper.ConfigFileUsed() == "" {
		location += " (not created yet, using defaults)"
	}

	fmt.Println("SkillGuard Configuration")
	fmt.Println("=======================")
	fmt.Printf("Default path: %s\n", cfg.DefaultPath)
	fmt.Printf("Threshold:    %d\n", cfg.Threshold)
	fmt.Printf("Config file:  %s\n", location)

	return nil
}

func setConfig(cmd *cobra.Command, args []string) error {
	if !cmd.Flags().Changed("path") && !cmd.Flags().Changed("threshold") {
		return fmt.Errorf("nothing to set: pass --path and/or --threshold")
	}

	cfg := loadConfig()

	if cmd.Flags().Changed("path") {
		cfg.DefaultPath = configPath
	}

	if cmd.Flags().Changed("threshold") {
		if err := validateThreshold(configThreshold); err != nil {
			return err
		}

		cfg.Threshold = configThreshold
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Configuration written to %s. Run 'skillguard config show' to verify.\n", cfg.path)

	return nil
}

func validateThreshold(threshold int) error {
	if threshold < 0 || threshold > 100 {
		return fmt.Errorf("threshold must be between 0 and 100, got %d", threshold)
	}

	return nil
}

type Config struct {
	viper       *viper.Viper
	path        string
	DefaultPath string `mapstructure:"default_path"`
	Threshold   int    `mapstructure:"threshold"`
}

// loadConfig reads ~/.skillguard.yaml, falling back to built-in defaults.
// Reading never writes: creating a config file as a side effect of every scan
// surprised users and polluted their home directory.
func loadConfig() *Config {
	v := viper.New()
	v.SetConfigName(configName)
	v.SetConfigType("yaml")

	home := homeDir()
	v.AddConfigPath(home)
	v.AddConfigPath(".")

	v.SetDefault("default_path", filepath.Join(home, ".agents", "skills"))
	v.SetDefault("threshold", defaultThreshold)

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			fmt.Fprintf(os.Stderr, "Warning: ignoring unreadable config: %v\n", err)
		}
	}

	cfg := &Config{
		viper: v,
		path:  filepath.Join(home, configName+".yaml"),
	}

	// Without this the struct keeps its zero values and every configured
	// setting is silently ignored.
	if err := v.Unmarshal(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: ignoring malformed config: %v\n", err)
	}

	if cfg.DefaultPath == "" {
		cfg.DefaultPath = filepath.Join(home, ".agents", "skills")
	}

	if cfg.Threshold == 0 {
		cfg.Threshold = defaultThreshold
	}

	return cfg
}

// Save writes the configuration, overwriting any existing file. SafeWriteConfig
// refuses to overwrite, which made 'config set' fail for everyone who already
// had a config file.
func (c *Config) Save() error {
	c.viper.Set("default_path", c.DefaultPath)
	c.viper.Set("threshold", c.Threshold)

	target := c.viper.ConfigFileUsed()
	if target == "" {
		target = c.path
	}

	return c.viper.WriteConfigAs(target)
}

func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}

	return os.Getenv("HOME")
}

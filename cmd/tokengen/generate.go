/*
Copyright © 2024 Andy Lo-A-Foe <andy.loafoe@gmail.com>
*/
package main

import (
	"fmt"
	"github.com/loafoe/caddy-token/keys"
	"github.com/spf13/cobra"
	"os"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g"},
	Short:   "Generate a new token",
	Long:    `Generate a new token. This command will generate a new token based on the parameters provided.`,
	Run:     tokenGenerate,
}

func tokenGenerate(cmd *cobra.Command, args []string) {
	key, _ := cmd.Flags().GetString("key")
	version, _ := cmd.Flags().GetString("version")
	org, _ := cmd.Flags().GetString("organization")
	env, _ := cmd.Flags().GetString("environment")
	region, _ := cmd.Flags().GetString("region")
	project, _ := cmd.Flags().GetString("project")
	scopes, _ := cmd.Flags().GetStringSlice("scopes")
	if org == "" || region == "" || version == "" {
		fmt.Println("Please provide all required parameters (at least: organization, region, version)")
		os.Exit(1)
	}
	apiKey, err := keys.GenerateAPIKey(version, key, org, env, region, project, scopes)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	fmt.Println(apiKey)
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringP("key", "k", "", "Key to use for token generation")
	generateCmd.Flags().StringP("version", "v", "2", "Token version (default: 2)")
	generateCmd.Flags().StringP("organization", "o", "", "Organization ID")
	generateCmd.Flags().StringP("environment", "e", "", "Environment ID")
	generateCmd.Flags().StringP("region", "r", "", "Region ID")
	generateCmd.Flags().StringP("project", "p", "", "Project ID")
	generateCmd.Flags().StringSliceP("scopes", "s", []string{}, "Scopes")
}

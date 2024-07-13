/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/loafoe/caddy-token"
	"math/big"
	"strings"

	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g"},
	Short:   "Generate a new token.",
	Long:    `Generate a new token. This command will generate a new token based on the parameters provided.`,
	Run:     tokenGenerate,
}

func tokenGenerate(cmd *cobra.Command, args []string) {
	org, _ := cmd.Flags().GetString("organization")
	env, _ := cmd.Flags().GetString("environment")
	region, _ := cmd.Flags().GetString("region")
	project, _ := cmd.Flags().GetString("project")
	if org == "" || env == "" || region == "" || project == "" {
		fmt.Println("Please provide all required parameters")
		return
	}
	randomCount := 24
	bail := 3
	for {
		if bail <= 0 {
			fmt.Println("Failed to generate a valid token")
			return
		}
		randomString := generateRandomString(randomCount)
		var newToken token.Key
		newToken.Organization = org
		newToken.Environment = env
		newToken.Region = region
		newToken.Project = project
		newToken.Token = randomString
		marshalled, _ := json.Marshal(newToken)
		key := base64.StdEncoding.EncodeToString(marshalled)
		if strings.HasSuffix(key, "=") {
			randomCount = randomCount + 1
			bail = bail - 1
			continue
		}
		// We have a good-looking newToken, return it
		fmt.Printf("%s%s\n", token.Prefix, key)
		return
	}
}

// generateRandomString generates a random alphanumeric string of length n.
func generateRandomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringP("organization", "o", "", "Organization ID")
	generateCmd.Flags().StringP("environment", "e", "", "Environment ID")
	generateCmd.Flags().StringP("region", "r", "", "Region ID")
	generateCmd.Flags().StringP("project", "p", "", "Project ID")
}

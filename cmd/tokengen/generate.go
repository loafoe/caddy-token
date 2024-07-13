/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

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
	randomString := generateRandomString(24)
	fmt.Println("generate called", randomString)
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

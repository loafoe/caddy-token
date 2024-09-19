package main

import (
	"fmt"
	"github.com/loafoe/caddy-token/keys"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var verifyCmd = &cobra.Command{
	Use:     "verify",
	Aliases: []string{"v"},
	Short:   "Verify a token.",
	Long:    `Verify a a token. This command will verify a token based on the parameters provided.`,
	Run:     tokenVerify,
}

func tokenVerify(cmd *cobra.Command, args []string) {
	key, _ := cmd.Flags().GetString("key")
	token, _ := cmd.Flags().GetString("token")
	if key == "" || token == "" {
		fmt.Println("Please provide all required parameters")
		return
	}
	ok, apiKey, err := keys.VerifyAPIKey(token, key)
	if !ok {
		fmt.Println(err)
		return
	}
	fmt.Println(apiKey)
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP("key", "k", "", "Key to use for token verification")
	verifyCmd.Flags().StringP("token", "t", "", "Token to verify")
}

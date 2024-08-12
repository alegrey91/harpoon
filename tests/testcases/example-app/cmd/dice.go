/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alegrey91/seccomp-test-coverage/pkg/randomic"
)

var faces int

// diceCmd represents the dice command
var diceCmd = &cobra.Command{
	Use:   "dice",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(randomic.ThrowDice(faces))
	},
}

func init() {
	rootCmd.AddCommand(diceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// diceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	diceCmd.Flags().IntVarP(&faces, "nfaces", "n", 6, "Number of the dice faces")
}

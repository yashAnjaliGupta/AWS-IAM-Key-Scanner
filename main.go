// Created By: Yash Gupta
// Name: AWS IAM Key Scanner

// For this code it Identifies the AWS IAM keys in the git repository and test the keys to see if they are valid.
// If the keys are valid, it prints the file name, commit hash, author, commit message and the keys.
// It Identifies the AWS IAM keys valid for if a successful request is made to the S3 API or creates Access Denied error.

package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type validAWSKeysinfo struct {
	FileName   string
	CommitHash string
	Author     string
	Message    string
	AccessKey  string
	SecretKey  string
}

func main() {
	// Open the repository in the current directory
	r, err := git.PlainOpen("Devops-Node")
	if err != nil {
		fmt.Printf("Error opening repository: %v\n", err)
		os.Exit(1)
	}

	// Get the HEAD reference
	ref, err := r.Head()
	if err != nil {
		fmt.Printf("Error getting HEAD reference: %v\n", err)
		os.Exit(1)
	}

	// Regex to match AWS IAM keys
	accessKeyRegex := regexp.MustCompile(`(^|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{20}([^A-Za-z0-9/+=]|$)`)
	secretKeyRegex := regexp.MustCompile(`(^|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}([^A-Za-z0-9/+=]|$)`)

	var validAWSKeys []validAWSKeysinfo
	// Get the commit object of the latest commit
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		fmt.Printf("Error getting commit object: %v\n", err)
		os.Exit(1)
	}

	// Get the tree of the commit to scan the lastest Commit for AWS IAM keys
	tree, err := commit.Tree()
	tree.Files().ForEach(func(file *object.File) error {
		contents, err := file.Contents()
		if err != nil {
			fmt.Printf("Error reading file contents: %v\n", err)
			os.Exit(1)
		}
		// Search the file contents for AWS IAM keys
		accessKeys := accessKeyRegex.FindAllString(string(contents), -1)
		secretKeys := secretKeyRegex.FindAllString(string(contents), -1)

		for _, accessKey := range accessKeys {
			for _, secretKey := range secretKeys {
				accessKey = stripNewlines(accessKey)
				secretKey = stripNewlines(secretKey)
				// Test the IAM keys
				if testIAMKeys(accessKey, secretKey) {
					gc := validAWSKeysinfo{
						FileName:   file.Name,
						CommitHash: commit.Hash.String(),
						Author:     fmt.Sprintf("%s <%s>", commit.Author.Name, commit.Author.Email),
						Message:    commit.Message,
						AccessKey:  accessKey,
						SecretKey:  secretKey,
					}
					validAWSKeys = append(validAWSKeys, gc)
				}
			}
		}
		return nil
	})
	// Iterate through the commit history
	commits := make([]*object.Commit, 0)
	for commit != nil {
		commits = append(commits, commit)
		parents := commit.Parents()
		if parents == nil {
			break
		}
		commit = nil
		parents.ForEach(func(parent *object.Commit) error {
			commit = parent
			return nil
		})
	}

	// Iterate through the commits in reverse order
	for i := len(commits) - 1; i >= 0; i-- {
		commit := commits[i]
		tree, err := getCommitDifferences(r, commit)
		if err != nil {
			fmt.Printf("Error getting patch: %v\n", err)
			continue
		}
		// Search the patch for AWS IAM keys
		patch, err := tree.Patch()
		for _, filePatch := range patch.FilePatches() {
			_, toFile := filePatch.Files()
			for _, chunk := range filePatch.Chunks() {

				accessKeys := accessKeyRegex.FindAllString(string(chunk.Content()), -1)
				secretKeys := secretKeyRegex.FindAllString(string(chunk.Content()), -1)

				for _, accessKey := range accessKeys {
					for _, secretKey := range secretKeys {

						accessKey = stripNewlines(accessKey)
						secretKey = stripNewlines(secretKey)

						if testIAMKeys(accessKey, secretKey) {
							gc := validAWSKeysinfo{
								FileName:   toFile.Path(),
								CommitHash: commit.Hash.String(),
								Author:     fmt.Sprintf("%s <%s>", commit.Author.Name, commit.Author.Email),
								Message:    commit.Message,
								AccessKey:  accessKey,
								SecretKey:  secretKey,
							}
							validAWSKeys = append(validAWSKeys, gc)
						}
					}
				}
			}
		}
	}
	// Create a map to keep track of unique validAWSKeysinfo values
	uniqueCommits := make(map[validAWSKeysinfo]struct{})

	// Loop over the validAWSKeys slice and add each unique validAWSKeysinfo to the map
	for _, commit := range validAWSKeys {
		uniqueCommits[commit] = struct{}{}
	}

	// Create a new slice to store the unique validAWSKeysinfo values
	uniqueCommitsSlice := make([]validAWSKeysinfo, 0, len(uniqueCommits))

	// Loop over the keys of the map and append each validAWSKeysinfo to the new slice
	for commit := range uniqueCommits {
		uniqueCommitsSlice = append(uniqueCommitsSlice, commit)
	}

	// Replace the validAWSKeys slice with the new slice of unique validAWSKeysinfo values
	validAWSKeys = uniqueCommitsSlice
	printvalidAWSKeysinfo(validAWSKeys)
}

func printvalidAWSKeysinfo(commits []validAWSKeysinfo) {
	for _, commit := range commits {
		fmt.Printf("File: %s\n", commit.FileName)
		fmt.Printf("Commit Hash: %s\n", commit.CommitHash)
		fmt.Printf("Author: %s\n", commit.Author)
		fmt.Printf("Message: %s\n", commit.Message)
		fmt.Printf("Access Key: %s\n", commit.AccessKey)
		fmt.Printf("Secret Key: %s\n", commit.SecretKey)
		fmt.Println()
	}
}

// Function to get difference between two commits
func getCommitDifferences(r *git.Repository, commit *object.Commit) (object.Changes, error) {
	var parent *object.Commit
	parents := commit.Parents()
	if parents != nil {
		parents.ForEach(func(p *object.Commit) error {
			parent = p
			return nil
		})
	}
	if parent == nil {
		return nil, nil
	}
	parentTree, err := parent.Tree()
	if err != nil {
		return nil, err
	}
	commitTree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	Changes, err := parentTree.Diff(commitTree)
	return Changes, err
}

// funtion to test IAM keys
func testIAMKeys(accessKey, secretKey string) bool {
	// Create a new session with the IAM keys

	sess, err := createSession(accessKey, secretKey)
	if err != nil {
		fmt.Println("Error creating session:", err)
		return false
	}
	// Create an S3 service client
	svc := s3.New(sess)

	// Make a basic API call to list S3 buckets
	_, err = svc.ListBuckets(&s3.ListBucketsInput{})
	// fmt.Println(err)
	if err != nil {
		// Check if the error is an authorization error
		if aerr, ok := err.(awserr.Error); ok {
			// Check if the error code is "AccessDenied" (403 status code)
			if aerr.Code() == "AccessDenied" {
				return true
			}
		}
		return false
	}
	// fmt.Println(result)
	return true
}

// function to create session
func createSession(accessKey, secretKey string) (*session.Session, error) {
	config := aws.Config{
		Region:      aws.String("us-east-1"), // Change to your preferred region
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	}

	return session.NewSession(&config)
}

// function to strip newlines
func stripNewlines(s string) string {
	// Remove newlines from the beginning of the string
	for len(s) > 0 && s[0] == '\n' {
		s = s[1:]
	}

	// Remove newlines from the end of the string
	for len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}

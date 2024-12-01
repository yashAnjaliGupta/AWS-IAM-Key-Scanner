package main

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

// Defined a proper structure for validAWSKeysinfo that represents information about valid AWS IAM keys
type validAWSKeysinfo struct {
	FileName   string
	CommitHash string
	Branch     string
	Author     string
	Message    string
	AccessKey  string
	SecretKey  string
}

// Regular expressions to match AWS IAM keys
var (
	accessKeyRegex = regexp.MustCompile(`(^|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{20}([^A-Za-z0-9/+=]|$)`)
	secretKeyRegex = regexp.MustCompile(`(^|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}([^A-Za-z0-9/+=]|$)`)
)

func main() {
	// Open the repository in the current directory
	r, err := git.PlainOpen("Devops-Node") //here the repository is in the same local system folder, so we can directly use the name of the repository
	if err != nil {
		fmt.Printf("Error opening repository: %v\n", err)
		os.Exit(1)
	}

	var validAWSKeys []validAWSKeysinfo //here we will store validAWSKyes structured objects

	// Iterate through all branches in the repository
	branches, err := r.Branches()
	if err != nil {
		fmt.Printf("Error getting branches: %v\n", err)
		os.Exit(1)
	}

	err = branches.ForEach(func(ref *plumbing.Reference) error {
		fmt.Printf("Scanning %s branch\n \n", ref.Name().Short())

		// Get the commit object of the latest commit on the branch
		commit, err := r.CommitObject(ref.Hash())
		if err != nil {
			return err
		}

		// Get the tree of the commit to scan for AWS IAM keys
		tree, err := commit.Tree()
		if err != nil {
			return err
		}

		// Iterate through the files in the tree
		tree.Files().ForEach(func(file *object.File) error {
			contents, err := file.Contents()
			if err != nil {
				return err
			}

			// Search the file contents for AWS IAM keys
			accessKeys := accessKeyRegex.FindAllString(string(contents), -1)
			secretKeys := secretKeyRegex.FindAllString(string(contents), -1)

			//Introducing mutex lock for multi threading and parallel programming so that it can execute faster
			var wg sync.WaitGroup
			var mu sync.Mutex

			// Iterate through IAM key pairs found in the file
			for _, accessKey := range accessKeys {
				for _, secretKey := range secretKeys {
					accessKey = sliceNewLines(accessKey)
					secretKey = sliceNewLines(secretKey)

					// Increment the WaitGroup counter
					wg.Add(1)

					// Concurrently validate IAM keys
					go func(accessKey, secretKey string) {
						defer wg.Done()

						// Validate the IAM keys using access and secret key pairs
						if validateIAMKeyWithAPI(accessKey, secretKey) {

							mu.Lock()

							// Create a validAWSKeysinfo struct
							gc := validAWSKeysinfo{
								FileName:   file.Name,
								CommitHash: commit.Hash.String(),
								Branch:     ref.Name().Short(),
								Author:     fmt.Sprintf("%s <%s>", commit.Author.Name, commit.Author.Email),
								Message:    commit.Message,
								AccessKey:  accessKey,
								SecretKey:  secretKey,
							}

							// Append to the list of valid keys
							validAWSKeys = append(validAWSKeys, gc)
							mu.Unlock()
						}
					}(accessKey, secretKey)
				}
			}

			// Wait for all IAM key validations in the file to complete
			wg.Wait()

			return nil
		})

		// BASELINE DEFINITION
		// Iterate through the commit history
		commits := make([]*object.Commit, 0)
		iter, err := r.Log(&git.LogOptions{})
		if err != nil {
			fmt.Printf("Error getting commit history: %v\n", err)
			os.Exit(1)
		}

		// Fetch commits
		err = iter.ForEach(func(commit *object.Commit) error {
			commits = append(commits, commit)
			return nil
		})
		if err != nil {
			fmt.Printf("Error iterating through commit history: %v\n", err)
			os.Exit(1)
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
			if err != nil {
				fmt.Printf("Error getting patch: %v\n", err)
			}

			for _, filePatch := range patch.FilePatches() {
				_, toFile := filePatch.Files()

				for _, chunk := range filePatch.Chunks() {
					accessKeys := accessKeyRegex.FindAllString(string(chunk.Content()), -1)
					secretKeys := secretKeyRegex.FindAllString(string(chunk.Content()), -1)

					// Iterate through IAM key pairs found in the patch
					for _, accessKey := range accessKeys {
						for _, secretKey := range secretKeys {
							accessKey = sliceNewLines(accessKey)
							secretKey = sliceNewLines(secretKey)

							// Validate IAM keys, here we are checking for validation only on the commit difference and not reading the complete file again
							if validateIAMKeyWithAPI(accessKey, secretKey) {
								// Create a validAWSKeysinfo struct
								gc := validAWSKeysinfo{
									FileName:   toFile.Path(),
									CommitHash: commit.Hash.String(),
									Branch:     ref.Name().Short(),
									Author:     fmt.Sprintf("%s <%s>", commit.Author.Name, commit.Author.Email),
									Message:    commit.Message,
									AccessKey:  accessKey,
									SecretKey:  secretKey,
								}
								// Append to the list of valid keys
								validAWSKeys = append(validAWSKeys, gc)
							}
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error iterating through branches: %v\n", err)
		os.Exit(1)
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

	// Print the valid AWS IAM key information
	if len(validAWSKeys) > 0 {
		fmt.Println("\nThe valid AWS IAM keys with commit details are:\n")
	} else {
		fmt.Println("\nThere is no Valid AWS IAM keys in this git repository\n")
	}
	printValidAWSKeysInfo(validAWSKeys)
}

// printValidAWSKeysInfo prints information about valid AWS IAM keys
func printValidAWSKeysInfo(commits []validAWSKeysinfo) {
	for _, commit := range commits {
		fmt.Printf("Branch: %s\n", commit.Branch)
		fmt.Printf("File: %s\n", commit.FileName)
		fmt.Printf("Commit Hash: %s\n", commit.CommitHash)
		fmt.Printf("Author: %s\n", commit.Author)
		fmt.Printf("Message: %s\n", commit.Message)
		fmt.Printf("Access Key: %s\n", commit.AccessKey)
		fmt.Printf("Secret Key: %s\n", commit.SecretKey)
		fmt.Println()
	}
}

// getCommitDifferences gets the differences between two commits
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
	changes, err := parentTree.Diff(commitTree)
	return changes, err
}

// validateIAMKeyWithAPI validates AWS IAM key with AWS API
func validateIAMKeyWithAPI(accessKey, secretKey string) bool {
	// Create a new AWS session with the provided access key and secret key
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	})
	if err != nil {
		fmt.Printf("Error creating AWS session: %v\n", err)
		return false
	}
	// Create a new IAM client with the session
	svc := iam.New(sess)

	// Call the ListUsers API to check if the IAM key is valid
	_, err = svc.GetUser(&iam.GetUserInput{})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "InvalidClientTokenId" {
				fmt.Printf("INVALID:  The accessKey %s is Invalid or Expired\n\n", accessKey)
				return false
			}
			if aerr.Code() == "SignatureDoesNotMatch" {
				fmt.Printf("NOT A VALID PAIR:  The accessKey %s is valid but the seceretKey %s for this accessKey is not correct.\n\n", accessKey, secretKey)
				return false
			}
		}
		return false
	}
	// If the API call succeeds, the IAM key is valid
	return true
}

// sliceNewLines function removes newlines from the beginning and end of a string
func sliceNewLines(s string) string {
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

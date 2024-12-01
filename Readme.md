code summary:

1.  Git Repository Scanning:

    - The program first scan a Git repository
    - It iterates through all branches and commits in the repository, and read contents of those files.

2.  AWS IAM Key Detection:

    - Using the regular expressions to identify AWS IAM access and secret keys in the contents of Git repository files.
    - We will identify the valid access and secret key patterns.
    - Now after identify those patterns, we will iterate nested loops to check each accessKey and secretKey combination.

3.  Validating AWS IAM Key Pairs (with multithreading):


    - Implemented a function to validate IAM key pairs after generating new session and make aws API call.
    - - Here on calling that function, I have implemented Multithreading using mutex lock for faster and parallel execution.

4.  Commit Analysis:

    - Now to read other commits, we are not reading the whole file again, instead we will just read commit difference contents. This will enhance performance of the program.
    - Examines commit history to identify IAM keys in both current and previous commits.
    - Retrieves commit differences and analyzes patches for IAM key changes.

5.  AWS API Validation:

    - Validates IAM keys using AWS API calls through the `validateIAMKeyWithAPI` function.
    - Checks for key validity, expiration, and correctness of key pairs.

6.  Output and Deduplication:
    - After checking for git repository and all commits, we will store those valid IAM key pairs into unique map so that we can avoid duplication.
    - Defined the proper structure for the Outputs that has information about valid AWS IAM keys, including branch, file, commit hash, author, message, access key, and secret key.

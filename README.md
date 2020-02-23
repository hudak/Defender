# Even Defender

## Prerequisites
- Python 3.7
- [pipenv](https://pipenv.kennethreitz.org/en/latest/)
- AWS CLI
- [aws-vault](https://github.com/99designs/aws-vault)

## Setup
1. Add security profile to aws-vault
    ```shell script
    aws-vault add security
    # Access Key: AKIAIUFNQ2WCOPTEITJQ
    # Secret Key: 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
    ```

2. Verify account access with provided aws wrapper
    ```shell script
    cat \
      <(./aws sts get-caller-identity) \
      <(AWS_PROFILE=target_security ./aws sts get-caller-identity)
    ```

## Objectives

1. Download CloudTrail Logs
    ```shell script
    ./aws s3 sync 's3://flaws2-logs' .
    ls -lR AWSLogs
    ```

2. Access Target Account
    - Added target_security profile to provided aws_config
    - Use AWS_PROFILE env variable to switch profiles
    ```shell script
    AWS_PROFILE=target_security ./aws s3 ls
    ```

3. Unzip & parse log records 
    ```shell script
    pipenv run describe_events
    ```

4. Identify credential theft
    - Script will search for non-AWS source IP addresses in records
    ```shell script
    pipenv run find_intruders
    ```
    - Results can be augmented with assumed IAM role info if provided
    ```shell script
    pipenv run find_intruders -r <(AWS_PROFILE=target_security ./aws iam list-roles)
    ```

5. Identify public resource
    - Simple script unwraps policyText from get-response-policy response
    ```shell script
    AWS_PROFILE=target_security ./aws ecr get-repository-policy --repository-name level2 | pipenv run python parse_policy_text.py
    ```

6. Query Records

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
    ./aws sts get-caller-identity
    ```

## Objectives

1. Download CloudTrail Logs

2. Access Target Account

3. Unzip & parse log records 

4. Identify credential theft

5. Identify public resource

6. Query Records

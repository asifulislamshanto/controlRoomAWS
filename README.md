# AWS Role Assumption Script Using Boto3

This project contains a Python script that uses the AWS SDK for Python (Boto3) to assume roles across multiple AWS accounts. The script allows users to securely provide AWS credentials and assume specified IAM roles in different target AWS accounts, retrieving temporary security credentials for further AWS operations.

## Features

- Takes AWS Access Key, Secret Key, and optionally a Session Token as input.
- Assumes a specified role in multiple AWS accounts.
- Outputs temporary AWS credentials (Access Key, Secret Key, and Session Token) for the assumed role.
- Provides error handling in case of invalid credentials or failed role assumptions.

## Requirements

- Python 3.x
- Boto3 library

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/asifulislamshanto/aws-role-assumption-script.git

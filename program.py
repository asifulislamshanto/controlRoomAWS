#Control Room AWS Automation Script



import boto3
from botocore.exceptions import ClientError

def assume_role(account_id, role_name, access_key, secret_key, session_token=None):
    """
    This function assumes an IAM role in a target AWS account.

    Parameters:
    - account_id: The AWS account ID where the role exists.
    - role_name: The name of the role to assume.
    - access_key: The AWS access key for authentication.
    - secret_key: The AWS secret key for authentication.
    - session_token: Optional session token, used if MFA or temporary session is required.

    Returns:
    - credentials: Temporary credentials (AccessKeyId, SecretAccessKey, SessionToken) 
      for the assumed role.
    """

    # Create a new session using the provided AWS credentials.
    if session_token:
        # If session_token is provided, include it in the session.
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
    else:
        # Otherwise, create a session with just the access key and secret key.
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    # Create a client for AWS Security Token Service (STS) to assume roles.
    sts_client = session.client('sts')

    # Construct the ARN (Amazon Resource Name) of the role to assume in the target account.
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    try:
        # Call STS to assume the role and get temporary security credentials.
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AssumedRoleSession'  # Session name for the assumed role.
        )

        # Extract the temporary credentials from the response.
        credentials = response['Credentials']
        return credentials

    except ClientError as e:
        # If an error occurs (e.g., invalid credentials or permissions), print the error message.
        print(f"Error assuming role: {e}")
        return None

def main():
    """
    The main function handles user input for credentials, and iterates through 
    target AWS accounts to assume roles in each account.
    """

    # Prompt the user to enter their AWS Access Key and Secret Key.
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")

    # Optionally, prompt for a session token (can be skipped if not required).
    session_token = input("Enter your AWS Session Token (or press enter if not required): ") or None

    # Define a list of target AWS accounts and corresponding role names to assume.
    accounts = [
        {'account_id': '123456789012', 'role_name': 'YourRoleName1'},
        {'account_id': '098765432109', 'role_name': 'YourRoleName2'},
        # Additional accounts and roles can be added to this list.
    ]

    # Loop through the list of accounts and assume roles for each one.
    for account in accounts:
        # Call the assume_role function for each account and role.
        credentials = assume_role(account['account_id'], account['role_name'], access_key, secret_key, session_token)

        # If role assumption is successful, print the temporary credentials.
        if credentials:
            print(f"Assumed role in account {account['account_id']}:")
            print(f"Access Key: {credentials['AccessKeyId']}")
            print(f"Secret Key: {credentials['SecretAccessKey']}")
            print(f"Session Token: {credentials['SessionToken']}")
        else:
            # If role assumption fails, print a failure message.
            print(f"Failed to assume role for account {account['account_id']}")

# Check if the script is being run directly (as opposed to being imported as a module).
if __name__ == "__main__":
    main()

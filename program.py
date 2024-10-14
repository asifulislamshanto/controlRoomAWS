import boto3
from botocore.exceptions import ClientError

def assume_role(account_id, role_name, access_key, secret_key, session_token=None):
    """
    Assume a specified IAM role in the current AWS account.

    Parameters:
    - account_id: The AWS account ID.
    - role_name: The name of the role to assume.
    - access_key: AWS access key for authentication.
    - secret_key: AWS secret key for authentication.
    - session_token: Optional session token, used if MFA or temporary session is required.

    Returns:
    - session: Boto3 session with assumed role credentials.
    """
    if session_token:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
    else:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    sts_client = session.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AssumedRoleSession'
        )

        credentials = response['Credentials']
        assumed_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

        return assumed_session

    except ClientError as e:
        print(f"Error assuming role: {e}")
        return None

def list_resources(session):
    """
    List some resources (e.g., EC2 instances, S3 buckets) available in the assumed role's account.
    
    Parameters:
    - session: Boto3 session with assumed role credentials.
    """
    try:
        # List S3 buckets
        s3_client = session.client('s3')
        buckets = s3_client.list_buckets()['Buckets']
        print("S3 Buckets:")
        for bucket in buckets:
            print(f" - {bucket['Name']}")
    
        # List EC2 instances
        ec2_client = session.client('ec2')
        instances = ec2_client.describe_instances()['Reservations']
        print("\nEC2 Instances:")
        for reservation in instances:
            for instance in reservation['Instances']:
                print(f" - Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
    except ClientError as e:
        print(f"Error listing resources: {e}")

def main():
    """
    Main function to handle user input and workflow.
    """
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")
    session_token = input("Enter your AWS Session Token (or press enter if not required): ") or None
    account_id = input("Enter the AWS Account ID: ")
    role_name = input("Enter the IAM Role Name: ")

    # Step 1: Assume the selected role
    assumed_session = assume_role(account_id, role_name, access_key, secret_key, session_token)

    if assumed_session:
        print(f"\nSuccessfully assumed role: {role_name} in account {account_id}")
        
        # Step 2: List resources available under this role
        list_resources(assumed_session)
    else:
        print("Failed to assume role.")

# Run the script
if __name__ == "__main__":
    main()

import datetime
import json
import logging
import os
import uuid

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cognito_client = boto3.client("cognito-idp")
user_api_key_table = boto3.resource("dynamodb").Table(os.environ["USER_API_KEY_TABLE"])
api_key_throttle_table = boto3.resource("dynamodb").Table(os.environ["API_KEY_THROTTLE_TABLE"])

user_pool_id = os.environ["COGNITO_USER_POOL_ID"]

def create_api_key(user_id: str, throttling: dict) -> None:
    """
    Create an API key for a user and store it in DynamoDB with throttling settings.

    Args:
        user_id (str): The unique identifier for the user
        throttling (dict): Dictionary containing throttling configuration with:
            - window_duration (int): Duration of the throttling window in seconds
            - window_requests (int): Maximum number of requests allowed in the window

    Raises:
        KeyError: If required throttling settings are missing
        ClientError: If there's an error interacting with DynamoDB
    """
    api_key = str(uuid.uuid4())

    window_duration = throttling["window_duration"]
    window_requests = throttling["window_requests"]

    user_api_key_table.put_item(
        Item={
            "user_id": user_id,
            "api_key": api_key,
            "created_at": int(datetime.datetime.now().timestamp()),
            "window_duration": window_duration,
            "window_requests": window_requests
        }
    )


def lambda_handler(event: dict, context: object) -> dict:
    """
    Lambda function handler for creating a new user in Cognito and generating their API key.

    Args:
        event (dict): The Lambda event containing:
            - email (str): User's email address
            - password (str): Initial password for the user
            - throttling (dict): API throttling settings with:
                - window_duration (int): Duration of the throttling window in seconds
                - window_requests (int): Maximum number of requests allowed in the window
        context (LambdaContext): AWS Lambda runtime context object

    Returns:
        dict: Response with structure:
            - statusCode (int): HTTP status code (200 for success)
            - body (str): Success or error message

    Raises:
        ClientError: If there's an error with Cognito or DynamoDB operations
        KeyError: If required event parameters are missing
    """
    email = event["email"]
    password = event["password"]
    throttling = event["throttling"]

    cognito_client.admin_create_user(
        UserPoolId=user_pool_id,
        Username=email,
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )

    user = cognito_client.admin_get_user(UserPoolId=user_pool_id, Username=email)

    cognito_client.admin_set_user_password(
        UserPoolId=user_pool_id, Username=email, Password=password, Permanent=True
    )

    logger.debug(f"Created user: {json.dumps(user, default=str)}")
    user_attrs = user["UserAttributes"]

    sub_attr = list(filter(lambda x: x["Name"] == "sub", user_attrs))
    sub = sub_attr[0]["Value"]
    create_api_key(sub, throttling)

    return {"statusCode": 200, "body": "User created successfully"}


if __name__ == "__main__":
    event = {"email": "test@example.com", "password": "XXXXXXXX"}
    lambda_handler(event, None)

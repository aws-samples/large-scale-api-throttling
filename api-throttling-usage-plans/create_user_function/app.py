import datetime
import json
import logging
import os
import uuid

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cognito_client = boto3.client("cognito-idp")
table = boto3.resource("dynamodb").Table(os.environ["USER_API_KEY_TABLE"])
apigw_client = boto3.client("apigateway")

usage_plan_id = os.environ["USAGE_PLAN_ID"]
user_pool_id = os.environ["COGNITO_USER_POOL_ID"]


def create_api_key(user_id: str) -> None:
    """
    Create an API key for a user and store it in DynamoDB.

    Args:
        user_id (str): The unique identifier for the user

    Returns:
        None
    """
    api_key = str(uuid.uuid4())

    api_key_resp = apigw_client.create_api_key(
        name=f"{user_id}-key",
        value=api_key,
        description=f"API key for user {user_id}",
        enabled=True,
    )
    apigw_client.create_usage_plan_key(
        usagePlanId=usage_plan_id, keyId=api_key_resp["id"], keyType="API_KEY"
    )
    table.put_item(
        Item={
            "user_id": user_id,
            "api_key": api_key,
            "created_at": int(datetime.datetime.now().timestamp()),
        }
    )


def lambda_handler(event: dict, context: object) -> dict:
    """
    Lambda function handler for creating a new user.

    Args:
        event (dict): The Lambda event containing user details
        context (LambdaContext): The Lambda context

    Returns:
        dict: Response indicating success or failure
    """
    email = event["email"]
    password = event["password"]

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
    create_api_key(sub)

    return {"statusCode": 200, "body": "User created successfully"}


if __name__ == "__main__":
    event = {"email": "test@example.com", "password": "XXXXXXXX"}
    lambda_handler(event, None)

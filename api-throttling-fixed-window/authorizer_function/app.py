import json
import logging
import os
import sys
import datetime
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal

import jwt
import requests
from apikeymanager import UserApiKeyManager
from aws_lambda_powertools import Tracer
from functools import lru_cache

tracer = Tracer()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
user_pool_id = os.environ["COGNITO_USER_POOL_ID"]
client_id = os.environ["COGNITO_USER_POOL_CLIENT_ID"]
aws_region = os.environ["AWS_REGION"]
user_pool_issuer = f"https://cognito-idp.{aws_region}.amazonaws.com/{user_pool_id}"

user_api_key_table_name = os.environ["USER_API_KEY_TABLE"]
api_key_throttle_table = boto3.resource("dynamodb").Table(os.environ["API_KEY_THROTTLE_TABLE"])

api_key_manager = UserApiKeyManager(user_api_key_table_name)

@lru_cache(maxsize=1)
def get_keys(user_pool_iss):
    """
    Retrieve the JSON Web Key Set (JWKS) for the user pool.

    Args:
        user_pool_iss (str): The issuer URL for the Cognito user pool

    Returns:
        dict: Dictionary mapping key IDs to tuples of (RSA key, algorithm)
    """
    keys_url = f"{user_pool_iss}/.well-known/jwks.json"
    resp = requests.get(keys_url)
    jwks = resp.json()

    return {
        key_data["kid"]: (
            jwt.algorithms.RSAAlgorithm.from_jwk(key_data),
            key_data["alg"],
        )
        for key_data in jwks["keys"]
    }


keys = get_keys(user_pool_issuer)  # Cache the keys in the exec environment

@tracer.capture_method
def check_throttling(api_key: str, window_duration: int, window_requests: int) -> None:
    """
    Check and enforce API throttling limits for a given API key.

    Args:
        api_key (str): The API key to check throttling for
        window_duration (int): Duration of the throttling window in seconds
        window_requests (int): Maximum number of requests allowed in the window

    Raises:
        Exception: If rate limit is exceeded
        ClientError: If there's an error interacting with DynamoDB
    """
    current_time = int(datetime.datetime.now().timestamp())
    window_start = current_time - (current_time % window_duration)
    ttl = window_start + window_duration

    try: 
        response = api_key_throttle_table.update_item(
                Key={"api_key": api_key, "window": window_start},
                UpdateExpression="SET #count = if_not_exists(#count, :zero) + :inc",
                ConditionExpression="attribute_exists(#count)",
                ExpressionAttributeValues={
                    ":zero": Decimal("0"),
                    ":inc": Decimal("1"),
                },
                ExpressionAttributeNames={
                    '#count': 'count',
                },
                ReturnValues="UPDATED_NEW"
        )
        
        current_count = response["Attributes"]["count"]
        if current_count > window_requests:
            raise Exception("Rate limit exceeded")        

    except ClientError as e:
        response = api_key_throttle_table.put_item(
                Item={
                    "api_key": api_key,
                    "window": window_start,
                    "count": Decimal("1"),
                    "ttl": ttl
                }
            )

@tracer.capture_lambda_handler
def lambda_handler(event: dict, context: dict) -> dict:
    """
    Lambda function handler for API Gateway custom authorizer.

    Args:
        event (dict): The Lambda event containing authorization details including:
            - authorizationToken: Bearer token for authentication
            - methodArn: ARN of the API Gateway method being accessed
        context (LambdaContext): The Lambda context object

    Returns:
        dict: IAM policy document determining access with structure:
            - principalId: Identifier for the principal
            - policyDocument: IAM policy with Allow/Deny effect
            - context: Additional context for API Gateway

    Raises:
        Exception: If authorization fails for any reason
    """
    logger.debug(f"Received event: {json.dumps(event, indent=1)}")
    try:
        # Get the token from the Authorization header
        token = event["authorizationToken"].replace("Bearer ", "")

        # Get the methodArn from the event
        method_arn = event["methodArn"]

        # Validate the JWT token
        claims = validate_token(token)

        user_id = claims["sub"]
        api_key_throttling = api_key_manager.get_api_key_throttling(user_id)
        api_key = api_key_throttling["api_key"]
        window_duration = api_key_throttling["window_duration"]
        window_requests = api_key_throttling["window_requests"]

        check_throttling(api_key, window_duration, window_requests)

        logger.debug(f"Retrieved API key for user {user_id}")

        # Generate the IAM policy
        policy = generate_policy("user", "Allow", method_arn, claims, api_key)
        logger.info(f"Authorization successful for {claims['sub']}")

        return policy

    except Exception as e:
        logger.error(f"Authorization failed: {e}")
        return generate_policy("user", "Deny", method_arn, None)

@tracer.capture_method
def validate_token(token: str) -> dict:
    """
    Validate a JWT token and return its claims.

    Args:
        token (str): The JWT token to validate

    Returns:
        dict: The validated token claims containing user information and authentication details

    Raises:
        AssertionError: If token validation fails
        jwt.InvalidTokenError: If the token is invalid or expired
    """
    kid = jwt.get_unverified_header(token)["kid"]
    key, alg = keys[kid]
    logger.debug(f"Using key with KID: {kid} and algorithm: {alg}")

    payload = jwt.decode(
        token,
        key=key,
        algorithms=[alg],  # , audience=client_id, options={"verify_aud": True}
    )
    assert payload["client_id"] == client_id
    assert payload["iss"] == user_pool_issuer

    return payload

@tracer.capture_method
def generate_policy(principal_id: str, effect: str, resource: str, claims: dict | None, api_key: str | None = None) -> dict:
    """
    Generate an IAM policy document for API Gateway custom authorization.

    Args:
        principal_id (str): The unique identifier for the authenticated principal
        effect (str): The IAM policy effect ('Allow' or 'Deny')
        resource (str): The API Gateway method ARN to grant/deny access to
        claims (dict | None): The JWT claims to include in the request context, or None if unauthorized
        api_key (str | None, optional): The API key to include in usage plan tracking. Defaults to None.

    Returns:
        dict: An IAM policy document with the following structure:
            {
                "principalId": str,  # The provided principal ID
                "policyDocument": {   # The IAM policy
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": "execute-api:Invoke",
                        "Effect": str,  # The provided effect
                        "Resource": str  # The provided resource ARN
                    }]
                },
                "context": {          # Optional context values
                    "scope": str,     # Space-separated OAuth scopes
                    "sub": str,       # Subject identifier
                    "apiKey": str     # API key if provided
                }
            }
    """
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }

    if claims:  # In some failure cases, claims will be empty
        policy["context"] = {"sub": claims["sub"]}

    policy["usageIdentifierKey"] = api_key

    return policy

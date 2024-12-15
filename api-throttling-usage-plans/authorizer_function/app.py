import json
import logging
import os
import sys

import jwt
import requests
from apikeymanager import UserApiKeyManager

from functools import lru_cache

logger = logging.getLogger()
logger.setLevel(logging.INFO)
user_pool_id = os.environ["COGNITO_USER_POOL_ID"]
client_id = os.environ["COGNITO_USER_POOL_CLIENT_ID"]
aws_region = os.environ["AWS_REGION"]
user_pool_issuer = f"https://cognito-idp.{aws_region}.amazonaws.com/{user_pool_id}"

table_name = os.environ["USER_API_KEY_TABLE"]
api_key_manager = UserApiKeyManager(table_name)

@lru_cache(maxsize=1)
def get_keys(user_pool_iss: str) -> dict[str, tuple[object, str]]:
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


def lambda_handler(event: dict, context: object) -> dict:
    """
    Lambda function handler for API Gateway custom authorizer.

    Args:
        event (dict): The Lambda event containing authorization details
        context (LambdaContext): The Lambda context

    Returns:
        dict: IAM policy document determining access
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
        api_key = api_key_manager.get_api_key(user_id)

        logger.debug(f"Retrieved API key for user {user_id}")

        # Generate the IAM policy
        policy = generate_policy("user", "Allow", method_arn, claims, api_key)
        logger.info(f"Authorization successful for {claims['sub']}")

        return policy

    # Catch anything as we don't care at this point
    # API GW will replace the deny message anyway
    except Exception as e: 
        logger.error(f"Authorization failed: {e}")
        return generate_policy("user", "Deny", method_arn, None)


def validate_token(token: str) -> dict:
    """
    Validate a JWT token and return its claims.

    Args:
        token (str): The JWT token to validate

    Returns:
        dict: The validated token claims

    Raises:
        AssertionError: If token validation fails
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


def generate_policy(principal_id: str, effect: str, resource: str, claims: dict | None, api_key: str | None = None) -> dict:
    """
    Generate an IAM policy document for API Gateway authorization.

    Args:
        principal_id (str): The principal ID for the policy (typically user ID)
        effect (str): The effect of the policy ('Allow' or 'Deny')
        resource (str): The ARN of the resource being accessed
        claims (dict | None): The JWT claims if authorization was successful
        api_key (str | None): The API key to include in the context, if any

    Returns:
        dict: The generated IAM policy document
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

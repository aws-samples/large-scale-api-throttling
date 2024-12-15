import logging

import boto3
from botocore.exceptions import ClientError
from functools import lru_cache

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class UserApiKeyManager:
    """
    Manages the mapping between user identifiers and API keys in DynamoDB.
    """

    def __init__(self, table_name: str):
        """
        Initialize the UserApiKeyManager.

        Args:
            table_name (str): The name of the DynamoDB table
        """
        self.apigw_client = boto3.client("apigateway")
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(table_name)

    @lru_cache
    def get_api_key_throttling(self, user_id: str) -> dict:
        """
        Retrieve the API key and throttling settings for a user.

        Args:
            user_id (str): The unique identifier for the user

        Returns:
            dict: A dictionary containing:
                - api_key (str): The API key for the user
                - window_duration (int): Duration of the throttling window in seconds
                - window_requests (int): Maximum number of requests allowed in the window

        Raises:
            KeyError: If no API key exists for the user
            ClientError: If there's an error interacting with DynamoDB
        """
        try:
            response = self.table.get_item(Key={"user_id": user_id})

            return {
                "api_key": response["Item"]["api_key"],
                "window_duration": response["Item"]["window_duration"],
                "window_requests": response["Item"]["window_requests"]
            }
        except ClientError as e:
            logger.error(f"Error retrieving API key for user {user_id}: {str(e)}")
            raise
        except KeyError:
            logger.error(f"No API key found for user {user_id}")
            raise

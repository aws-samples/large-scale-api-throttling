import logging

import boto3
from botocore.exceptions import ClientError

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

    def get_api_key(self, user_id: str) -> str:
        """
        Retrieve the API key associated with a user ID from DynamoDB.

        Args:
            user_id (str): The unique identifier for the user

        Returns:
            str: The API key associated with the user

        Raises:
            ClientError: If there's an error accessing DynamoDB
            KeyError: If no API key exists for the user
        """
        try:
            response = self.table.get_item(Key={"user_id": user_id})

            return response["Item"]["api_key"]
        except ClientError as e:
            logger.error(f"Error retrieving API key for user {user_id}: {str(e)}")
            raise
        except KeyError:
            logger.error(f"No API key found for user {user_id}")
            raise

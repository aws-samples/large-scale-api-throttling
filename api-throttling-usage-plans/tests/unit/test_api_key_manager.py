import boto3
import pytest
from moto import mock_aws

from authorizer_function.apikeymanager import UserApiKeyManager


@mock_aws
def test_api_key_manager():
    api_key_table = "TestTable"
    dynamodb = boto3.client("dynamodb")
    dynamodb.create_table(
        TableName=api_key_table,
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    table = boto3.resource("dynamodb").Table(api_key_table)
    table.put_item(Item={"user_id": "test_user", "api_key": "test_key"})

    manager = UserApiKeyManager(api_key_table)

    # Test key that was inserted
    api_key = manager.get_api_key("test_user")
    assert api_key == "test_key"

    # Test getting a user that is not in the table
    with pytest.raises(KeyError):
        manager.get_api_key("test_user2")

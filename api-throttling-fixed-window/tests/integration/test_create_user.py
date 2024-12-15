import os
from importlib import reload

import pytest
from moto import mock_aws


@pytest.fixture(scope="module")
def aws_creds():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@mock_aws
def test_lambda_handler_success():
    # Setup
    pool_name = "test-pool-id"
    api_key_table = "test-api-key-table"

    import boto3

    cognito = boto3.client("cognito-idp")
    response = cognito.create_user_pool(PoolName=pool_name)
    user_pool_id = response["UserPool"]["Id"]

    dynamodb = boto3.client("dynamodb")
    dynamodb.create_table(
        TableName=api_key_table,
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )

    table = boto3.resource("dynamodb").Table(api_key_table)

    os.environ["COGNITO_USER_POOL_ID"] = user_pool_id
    os.environ["USER_API_KEY_TABLE"] = api_key_table

    from create_user_function import app

    reload(
        app
    )  # Necessary because of os variable caching in the top level of the module

    user_event = {"email": "test@example.com", "password": "TestPassword123!", "throttling": {
        "window_duration": 42,
        "window_requests": 42
    }}

    result = app.lambda_handler(user_event, None)

    assert result["statusCode"] == 200
    assert result["body"] == "User created successfully"

    items = table.scan()["Items"]

    assert len(items) == 1

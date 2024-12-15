import os
import uuid

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(scope="module")
def aws_creds():
    """Set up mock AWS credentials for testing"""
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_resources(aws_creds):
    """Set up mock AWS resources needed for testing"""
    with mock_aws():
        # Create Cognito User Pool
        cognito = boto3.client("cognito-idp")
        user_pool = cognito.create_user_pool(PoolName="test-pool")
        user_pool_id = user_pool["UserPool"]["Id"]

        # Create Cognito User Pool Client
        client = cognito.create_user_pool_client(
            UserPoolId=user_pool_id, ClientName="test-client", GenerateSecret=False
        )
        client_id = client["UserPoolClient"]["ClientId"]

        # Create DynamoDB table
        dynamodb = boto3.client("dynamodb")
        table_name = "test-user-api-keys"
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create API Gateway resources
        apigw = boto3.client("apigateway")
        api = apigw.create_rest_api(name="test-api")
        api_id = api["id"]

        usage_plan_name = "test-usage-plan"
        usage_plan = apigw.create_usage_plan(
            name=usage_plan_name, apiStages=[{"apiId": api_id, "stage": "prod"}]
        )

        os.environ["USER_API_KEY_TABLE"] = table_name
        os.environ["COGNITO_USER_POOL_ID"] = user_pool_id
        os.environ["COGNITO_USER_POOL_CLIENT_ID"] = client_id
        os.environ["USAGE_PLAN_ID"] = usage_plan["id"]
        os.environ["API_ID"] = api_id

        yield {
            "user_pool_id": user_pool_id,
            "client_id": client_id,
            "table_name": table_name,
            "api_id": api_id,
        }


def test_authorizer_integration(mock_resources):
    """Test the complete authorization flow including token validation and policy generation"""
    # Create a test user
    email = f"test.user{uuid.uuid4()}@example.com"
    password = "Test123!"

    # First create the user using the create_user Lambda
    from create_user_function.app import lambda_handler as create_user_handler

    create_event = {"email": email, "password": password}
    create_response = create_user_handler(create_event, None)
    assert create_response["statusCode"] == 200

    # Authenticate with Cognito to get tokens
    cognito = boto3.client("cognito-idp")
    auth_response = cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": password},
        ClientId=mock_resources["client_id"],
    )

    access_token = auth_response["AuthenticationResult"]["AccessToken"]

    # Get the user's API key from DynamoDB
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(mock_resources["table_name"])
    user_item = table.scan()["Items"][0]
    api_key = user_item["api_key"]

    # Create an authorizer event
    method_arn = f"arn:aws:execute-api:us-east-1:{os.environ.get('AWS_ACCOUNT_ID', '123456789012')}:{mock_resources['api_id']}/prod/GET/test"
    authorizer_event = {
        "type": "TOKEN",
        "authorizationToken": f"Bearer {access_token}",
        "methodArn": method_arn,
        "headers": {"x-api-key": api_key},
    }

    # Call the authorizer Lambda
    from authorizer_function.app import lambda_handler as authorizer_handler

    auth_response = authorizer_handler(authorizer_event, None)

    # Verify the response structure
    assert "policyDocument" in auth_response
    assert "Statement" in auth_response["policyDocument"]
    assert len(auth_response["policyDocument"]["Statement"]) > 0
    assert auth_response["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    assert method_arn in auth_response["policyDocument"]["Statement"][0]["Resource"]

    # Verify the usageIdentifierKey field has the correct key
    assert auth_response["usageIdentifierKey"] == api_key

import json
import boto3
import os
import hmac
import hashlib
import base64

#Create cognito client
cognito_client = boto3.client("cognito-idp")

#Environment variables
USER_POOL_ID = os.getenv("USER_POOL_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

def get_secret_hash(username):
    print("hash init")
    message = username + CLIENT_ID
    dig = hmac.new(CLIENT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
    print("hash completed")
    return base64.b64encode(dig).decode()

def check_user_exists(email):
    """ Check if the user already exists in Cognito """
    try:
        cognito_client.admin_get_user(
            UserPoolId=USER_POOL_ID,
            Username=email
        )
        return True  # User exists
    except cognito_client.exceptions.UserNotFoundException:
        return False  # User does not exist
    except Exception as e:
        print(f"Error checking user existence: {str(e)}")
        raise

def lambda_handler(event, context):
    try:
        body = json.loads(event["body"])

        name = body["name"]
        email = body["email"]
        password = body["password"]

        #Check if user already exists
        if check_user_exists(email):
            return {
                'statusCode': 400,
                'body': json.dumps({"msg": f"User with the email already exists"})
            }

        #Sign up user in Cognito
        response = cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=email,
            Password=password,
            SecretHash=get_secret_hash(email),
            UserAttributes=[
                {"Name": "name", "Value": name},
                {"Name": "email", "Value": email},
            ]
        )
        print("Response::", response)

        return {
            'statusCode': 200,
            'body': json.dumps({"msg": f"Success! Check your email for OTP"})
        }
    
    except Exception as e:
        return {
            'statusCode': 400,
            'body': json.dumps({"msg": "Error in signup", "error": str(e)})
        }

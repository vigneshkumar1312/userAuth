import boto3
import json
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

def lambda_handler(event, context):
    body = json.loads(event["body"])
    email = body["email"]
    password = body["password"]
    
    try:
        # Authenticate user
        response = cognito_client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=CLIENT_ID,
            AuthParameters={
                "SECRET_HASH": get_secret_hash(email),
                "USERNAME": email,
                "PASSWORD": password
            }
        )
        print("Response:",response)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Login successful",
                "id_token": response["AuthenticationResult"]["IdToken"],
                "access_token": response["AuthenticationResult"]["AccessToken"],
                "refresh_token": response["AuthenticationResult"]["RefreshToken"]
            })
        }
    
    except cognito_client.exceptions.NotAuthorizedException as e:
        print("ERROR::",e)
        return {"statusCode": 401, "body": json.dumps({"error": "Incorrect username or password"})}
    
    except cognito_client.exceptions.UserNotFoundException as e:
        print("ERROR::",e)
        return {"statusCode": 404, "body": json.dumps({"error": "User does not exist"})}
    
    except Exception as e:
        return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

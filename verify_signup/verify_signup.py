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
    otp = body["otp"]
    
    try:
        #Verify OTP with Cognito
        response = cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=email,
            SecretHash=get_secret_hash(email),
            ConfirmationCode=otp
        )
        
        return {
            "statusCode": 200,
            "body": json.dumps({"msg": "User verified! Signup Successful!"})
        }

    except cognito_client.exceptions.CodeMismatchException:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid OTP. Please enter the correct OTP."})
        }

    except cognito_client.exceptions.ExpiredCodeException:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "OTP expired. Request a new OTP and try again."})
        }

    except Exception as e:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"An error occurred: {str(e)}"})
        }

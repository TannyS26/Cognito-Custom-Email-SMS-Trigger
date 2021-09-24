import os
import json
import base64
import aws_encryption_sdk
import botocore.credentials
import botocore.session

from aws_encryption_sdk.identifiers import CommitmentPolicy
from urllib import request, parse


ACCESS_KEY = os.environ.get('ACCESS_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY')
TWILIO_SMS_URL = "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json"
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
DEFAULT_FROM_NUMBER = os.environ.get('DEFAULT_FROM_NUMBER')


generatorKeyId = os.environ.get('KEY_ALIAS')
keyIds = [os.environ.get('KEY_ID')]

kms_kwargs = dict(key_ids=keyIds)
sess = botocore.session.get_session()
sess._credentials = botocore.credentials.Credentials(
    access_key=ACCESS_KEY, secret_key=SECRET_KEY)
kms_kwargs["botocore_session"] = sess
client = aws_encryption_sdk.EncryptionSDKClient(
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
)
kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)


def send_sms(body, to):
    # insert Twilio Account SID into the REST API URL
    populated_url = TWILIO_SMS_URL.format(TWILIO_ACCOUNT_SID)
    post_params = {"To": to, "From": DEFAULT_FROM_NUMBER, "Body": body}

    # encode the parameters for Python's urllib
    data = parse.urlencode(post_params).encode()
    req = request.Request(populated_url)

    # add authentication header to request based on Account SID + Auth Token
    authentication = "{}:{}".format(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    base64string = base64.b64encode(authentication.encode('utf-8'))
    req.add_header("Authorization", "Basic %s" % base64string.decode('ascii'))

    try:
        # perform HTTP POST request
        with request.urlopen(req, data) as f:
            print("Twilio returned {}".format(str(f.read().decode('utf-8'))))
    except Exception as e:
        # something went wrong!
        return e


def lambda_handler(event, context):
    # Decrypt the secret code using encryption SDK.
    ciphertext = base64.b64decode(event['request']['code'])
    decrypted_plaintext, _ = client.decrypt(
        source=ciphertext, key_provider=kms_key_provider
    )
    plainTextCode = decrypted_plaintext.decode('utf-8')
    # PlainTextCode now has the decrypted secret.
    number = event['request']['userAttributes']['phone_number']

    if event['triggerSource'] == 'CustomSMSSender_SignUp':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_ResendCode':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_ForgotPassword':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_UpdateUserAttribute':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_VerifyUserAttribute':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_AdminCreateUser':
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomSMSSender_AccountTakeOverNotification':
        text = "Code: " + plainTextCode

    send_sms(text, number)
    return

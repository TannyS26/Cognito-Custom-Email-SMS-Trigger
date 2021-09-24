import os
import ssl
import base64
import smtplib
import aws_encryption_sdk
import botocore.credentials
import botocore.session

from aws_encryption_sdk.identifiers import CommitmentPolicy
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


ACCESS_KEY = os.environ.get('ACCESS_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY')
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_PORT = os.environ.get('EMAIL_PORT')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')

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


def send_email(subject, html, text, to):
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = DEFAULT_FROM_EMAIL
    message["To"] = to

    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html, "html"))
    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, context=context)
    server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    server.sendmail(DEFAULT_FROM_EMAIL, [to], message.as_string())
    server.close()


def lambda_handler(event, context):
    # Decrypt the secret code using encryption SDK.
    ciphertext = base64.b64decode(event['request']['code'])
    decrypted_plaintext, _ = client.decrypt(
        source=ciphertext, key_provider=kms_key_provider
    )
    plainTextCode = decrypted_plaintext.decode('utf-8')
    # PlainTextCode now has the decrypted secret.
    email = event['request']['userAttributes']['email']

    if event['triggerSource'] == 'CustomEmailSender_SignUp':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_ResendCode':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_ForgotPassword':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_UpdateUserAttribute':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_VerifyUserAttribute':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_AdminCreateUser':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode
    elif event['triggerSource'] == 'CustomEmailSender_AccountTakeOverNotification':
        subject = "Hello World"
        html = "Code: " + plainTextCode
        text = "Code: " + plainTextCode

    send_email(subject, html, text, email)
    return

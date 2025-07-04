from threading import Thread
from app import app
from mailjet_rest import Client
from flask import render_template, url_for
import re
import datetime
from dateutil.parser import parse


def send_contact_email(user, message, subject):
    api_key = app.config['MAILJET_KEY']
    api_secret = app.config['MAILJET_SECRET']
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    data = {
        'Messages': [
            {
                "From": {
                    "Name": 'Canoe Econfina',
                    "Email": app.config['MAIL_SENDER'],
                },
                "To": [
                    {
                        "Name": 'Canoe Econfina',
                        "Email": app.config['ADMIN_EMAIL']
                    }
                ],
                "Subject": subject + " from " + user.first_name,
                "ReplyTo": { "Email": user.email },
                "HTMLPart": render_template('email/contact-email.html',
                                         user=user, message=message)
            }
        ]
    }

    result = mailjet.send.create(data=data)

    if result.status_code == 200:
        print("Contact email sent from " + user.email)
    else:
        print("Contact email from " + user.email + " failed with code " + result.status_code)
    return result.status_code


def send_confirmation_email(user, message, subject):
    api_key = app.config['MAILJET_KEY']
    api_secret = app.config['MAILJET_SECRET']
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    data = {
        'Messages': [
            {
                "From": {
                    "Name": 'Canoe Econfina',
                    "Email": app.config['MAIL_SENDER'],
                },
                "To": [
                    {
                    "Email": user.email
                    }
                ],
                "Subject": "Confirmation email",
                "HTMLPart": render_template('email/confirmation-email.html',
                                         user=user, message=message, subject=subject),
                "TextPart": render_template('email/confirmation-email.txt',
                                         user=user, message=message, subject=subject)
            }
        ]
    }

    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        print("Confirmation email sent to " + user.email)
    else:
        print("Confirmation email to " + user.email + " failed to send with code " + result.status_code, result.reason)
    return result.status_code


def send_review_approval_email(review):
    api_key = app.config['MAILJET_KEY']
    api_secret = app.config['MAILJET_SECRET']
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    data = {
        'Messages': [
            {
                "From": {
                    "Name": 'Canoe Econfina',
                    "Email": app.config['MAIL_SENDER'],
                },
                "To": [
                    {
                        "Name": 'Canoe Econfina',
                        "Email": app.config['ADMIN_EMAIL']
                    }
                ],
                "Subject": "New review from " + review.name,
                "HTMLPart": render_template('email/review-approval-email.html',
                                            review=review)
            }
        ]
    }

    result = mailjet.send.create(data=data)

    if result.status_code == 200:
        print("Review email sent")
    else:
        print("Review email failed with code " + result.status_code)
    return result.status_code


def send_verification_email(user):
    api_key = app.config['MAILJET_KEY']
    api_secret = app.config['MAILJET_SECRET']
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    token = user.get_email_verification_token()

    data = {
        'Messages': [
            {
                "From": {
                    "Name": 'Canoe Econfina',
                    "Email": app.config['MAIL_SENDER'],
                },
                "To": [
                    {
                    "Email": user.email
                    }
                ],
                "Subject": "Please verify your email address",
                "HTMLPart": render_template('email/verification-email.html',
                                         user=user, token=token)
            }
        ]
    }

    result = mailjet.send.create(data=data)

    if result.status_code == 200:
        print("Verification email sent to " + user.email)
    else:
        print("Verification email to " + user.email + " failed with code " + result.status_code)
    return result.status_code


def send_password_reset_email(user):
    api_key = app.config['MAILJET_KEY']
    api_secret = app.config['MAILJET_SECRET']
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    token = user.get_email_verification_token()
    if user.password_hash == None:
        pw_type = 'set'
    else:
        pw_type = 'reset'

    data = {
        'Messages': [
            {
                "From": {
                    "Name": 'Canoe Econfina',
                    "Email": app.config['MAIL_SENDER'],
                },
                "To": [
                    {
                    "Email": user.email
                    }
                ],
                "Subject": pw_type.title() + ' your password',
                "ReplyTo": { "Email": user.email },
                "HTMLPart": render_template('email/set-password-email.html', \
                                         user=user, token=token, pw_type=pw_type)
            }
        ]
    }

    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        print(result.json())
    else:
        print("Password reset email failed to send with code " + str(result.status_code), result.reason)
    return result.status_code

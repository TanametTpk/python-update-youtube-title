# -*- coding: utf-8 -*-

import os
import flask
from flask import request
import requests
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import time
from gevent.pywsgi import WSGIServer
from werkzeug.utils import secure_filename

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

CLIENT_SECRETS_FILE = "cli_id.json"

SCOPES = ['https://www.googleapis.com/auth/youtube']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = flask.Flask(__name__)
app.secret_key = 'klfgag54a6__+++_+_=3(_^(+!_^(!+_^5g4fg.ag.algpa[];][;[4;[6;]2;62'

isSchedulerRunning = False
ID = ""
CUSTOM_TITLE = "คลิปนี้มี {} วิว"

cred = False

youtube = False

def refreshToken(client_id, client_secret, refresh_token):
    params = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
    }

    authorization_url = "https://www.googleapis.com/oauth2/v4/token"

    r = requests.post(authorization_url, data=params)

    if r.ok:
        return r.json()['access_token']
    else:
        return None

def refresh_api():
    global cred

    if not cred:
        return

    # Call refreshToken which creates a new Access Token
    access_token = refreshToken(cred.client_id, cred.client_secret, cred.refresh_token)

    # Pass the new Access Token to Credentials() to create new credentials
    credentials = google.oauth2.credentials.Credentials(access_token)

    cred.token = credentials.token

    # {'token': credentials.token,
    #         'refresh_token': credentials.refresh_token,
    #         'token_uri': credentials.token_uri,
    #         'client_id': credentials.client_id,
    #         'client_secret': credentials.client_secret,
    #         'scopes': credentials.scopes}

    # print(credentials_to_dict(cred))

    global youtube
    youtube = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=cred)

def updateYoutube():

    global ID
    global youtube

    if not youtube:
        print(ID)
        print("can not update, are you login yet?")
        return

    if os.path.exists("youtube_video_id.txt"):
        f = open("youtube_video_id.txt", encoding="utf-8")
        ID = f.readline()
    else:
        print("not found youtube_video_id")
        return

    if os.path.exists("title.txt"):
        f = open("title.txt", encoding="utf-8")
        CUSTOM_TITLE = f.readline()
    else:
        print("not found title")
        return

    video = youtube.videos().list(id = ID, part='snippet, id, statistics').execute()
    views = video["items"][0]["statistics"]["viewCount"]
    categoryId = video["items"][0]["snippet"]["categoryId"]
    description = video["items"][0]["snippet"]["description"]
    tags = video["items"][0]["snippet"]["tags"]

    if not "Techcast" in description:
        description = description + "\n\nScript นี้สร้างโดยช่อง Techcast (กดติดตามที่ลิงค์นี้ได้เลย)\nhttps://bit.ly/3hvHVXH"

    request = youtube.videos().update(
        part="snippet",
        body={
            "id": ID,
            "snippet": {
                "title": CUSTOM_TITLE.format(views),
                "description": description,
                "categoryId": categoryId,
                "tags":tags
            }
        }
    )

    response = request.execute()

    refresh_api()

@app.route('/')
def index():
    return print_index_table()

@app.route("/new")
def new():

    # global cred

    # if not cred:
    #     return "not found auth"

    # # Call refreshToken which creates a new Access Token
    # access_token = refreshToken(cred.client_id, cred.client_secret, cred.refresh_token)

    # # Pass the new Access Token to Credentials() to create new credentials
    # credentials = google.oauth2.credentials.Credentials(access_token)

    # cred = credentials

    # return credentials.token
    refresh_api()
    return "success"

@app.route('/uploader', methods = ['POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        f.save(secure_filename(CLIENT_SECRETS_FILE))
        return 'file uploaded successfully'

@app.route('/addTitle', methods = ['POST'])
def addTitle():
    if request.method == 'POST':
        title = request.form.get("title")
        print(title)
        f = open("title.txt", "w", encoding="utf-8")
        f.write(title)
        f.close()
        return 'add title successfully'

@app.route('/addId', methods = ['POST'])
def addId():
    if request.method == 'POST':
        id = request.form.get("clipid")
        f = open("youtube_video_id.txt", "w", encoding="utf-8")
        f.write(id)
        f.close()
        return 'add clip id successfully'

@app.route('/test')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    global youtube
    youtube = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

    return "success"


@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    global cred
    cred = credentials

    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return('Credentials successfully revoked.' + print_index_table())
    else:
        return('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/test">Start Sheduler</a></td>' +
            '<td>Start run automatic update youtube title</td></tr>' +
            '<tr><td><a href="/authorize">Login</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Use for remove credentials from server' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token (it\'s like logout)' +
            '</td></tr></table>' +
            '<form action = "/uploader" method = "POST" enctype = "multipart/form-data">' +
            '<h2>upload credidate</h2><input type = "file" name = "file" />' +
            '<input type = "submit"/>' +
            '</form>' +

            '<form action = "/addTitle" method = "POST" >' +
            '<h2>Title</h2><input type = "text" name = "title" />' +
            '<input type = "submit"/>' +
            '</form>' + 

            '<form action = "/addId" method = "POST" >' +
            '<h2>Youtube clip id</h2><input type = "text" name = "clipid" />' +
            '<input type = "submit"/>' +
            '</form>'
            )


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    scheduler = BackgroundScheduler() 
    scheduler.add_job(func=updateYoutube, trigger="interval", minutes=8)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    print("server is running at port 8080")
    http_server = WSGIServer(('', 8080), app)
    http_server.serve_forever()
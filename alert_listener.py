from flask import Flask, request
import subprocess
 
app = Flask(__name__)

@app.post("/alert")
def alert():
    msg = request.json.get("message", "NIDS Alert")
    subprocess.Popen(["./host_alert.sh", msg])
    return "OK"

app.run(host="127.0.0.1", port=9000)


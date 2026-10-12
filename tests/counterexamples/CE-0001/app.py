import subprocess

from flask import request


def run():
    subprocess.run(["ls", request.args["d"]], check=False)

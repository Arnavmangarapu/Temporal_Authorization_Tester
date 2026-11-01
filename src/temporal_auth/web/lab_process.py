"""Disposable target server using an inherited, already-bound loopback socket."""

import socket
import sys

import uvicorn
from document_lab.app import create_app


if __name__ == "__main__":
    listener = socket.socket(fileno=int(sys.argv[1]))
    uvicorn.Server(uvicorn.Config(create_app(), log_level="error", access_log=False,
                                 lifespan="on", ws="none")).run(sockets=[listener])

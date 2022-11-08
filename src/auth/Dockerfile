FROM snakepacker/python:all as builder

RUN python3.9 -m venv /usr/share/python3/app
RUN /usr/share/python3/app/bin/pip install -U pip

COPY requirements.txt /mnt/
RUN /usr/share/python3/app/bin/pip install -Ur /mnt/requirements.txt

FROM snakepacker/python:3.9 as api

COPY --from=builder /usr/share/python3/app /usr/share/python3/app

WORKDIR /src
COPY . .
CMD ["/usr/share/python3/app/bin/python3", "server.py"]

FROM golang:1.15.8-buster

RUN git clone https://github.com/decentralized-identity/kerigo.git /root/kerigo

WORKDIR /root/kerigo

RUN go build -o bob cmd/demo/bob/bob.go
RUN go build -o eve cmd/demo/eve/eve.go
RUN go build -o sam cmd/demo/sam/sam.go

FROM golang:1.22.1

RUN apt update && \
        apt upgrade && apt install -y wget clang llvm libbpf-dev curl git make sudo build-essential && \
        ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

ENTRYPOINT [ "tail", "-f", "/dev/null" ]

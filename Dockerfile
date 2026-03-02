FROM rust:1.93-bookworm

WORKDIR /usr/src/helm
COPY . .
RUN cp .env.template .env
RUN cargo build -p helm --release && mv target/release/helm /usr/local/bin/

EXPOSE 3333 9000

ENV HELM_API_PORT=3333
ENV HELM_P2P_PORT=9000

ENTRYPOINT ["helm"]

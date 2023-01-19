FROM rust:latest

WORKDIR /app

RUN mkdir -p 0700 /app/{src,lib,pkg/{master,clients}}

COPY . /app/

# COPY src/* /app/src/

# COPY Cargo.toml /app/Cargo.toml

# COPY lib/* /app/lib/

RUN cargo build --release

CMD [ "/app/target/release/server" ]
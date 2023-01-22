FROM rustlang/rust:nightly

RUN groupadd -r mam && useradd --no-log-init -r -g mam mam

WORKDIR /app

COPY --chown=mam:mam ./src /app/src
COPY --chown=mam:mam ./lib /app/lib
COPY --chown=mam:mam ./upload /app/upload
COPY --chown=mam:mam ./pkg /app/pkg
COPY --chown=mam:mam ./Cargo.toml /app/Cargo.toml
COPY --chown=mam:mam ./Rocket.toml /app/Rocket.toml

RUN chown -R mam:mam /app

USER mam:mam

RUN cargo build --release

CMD [ "/app/target/release/server" ]
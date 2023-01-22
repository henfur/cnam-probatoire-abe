# POC of MAM like application using ABE encryption

**Author:** Amaury JASPAR

**Credit:** [Fraunhofer-AISEC](https://github.com/Fraunhofer-AISEC) for the [rabe](https://github.com/Fraunhofer-AISEC/rabe) library

## ABE Implementation

The application uses the [rabe](https://github.com/Fraunhofer-AISEC/rabe) library from Fraunhofer-AISEC for all cryptographic operations. For now, only AC17-KPABE is usable through the API. Some code from the rabe-console application was re-used as a baseline for the [encryption](src/encryption/mod.rs) module. 

## Usage

### Requirements

Native installation requires the nightly version of the rust tool chain. See the [rust documentation](https://www.rust-lang.org/learn/get-started) for more information.

The program can then be launched for development purposes using `cargo run`. You can also build a release version which will provide better performance: `cargo build --release`

The application also provides a Dockerfile. Build the image and then run it with a port forward to the configured port in the [rocket config](Rocket.toml).

```bash
docker build . -t mam-server
docker run -p 8000:8000 mam-server:latest
```

# License

[MIT License](https://github.com/henfur/abe-mam-poc/blob/main/LICENSE.md)


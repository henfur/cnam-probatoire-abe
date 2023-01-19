# POC of MAM like application using ABE encryption

**Author:** Amaury JASPAR

**Credit:** [Fraunhofer-AISEC](https://github.com/Fraunhofer-AISEC) for the [rabe](https://github.com/Fraunhofer-AISEC/rabe) library

## ABE Implementation

The application uses the [rabe](https://github.com/Fraunhofer-AISEC/rabe) library from Fraunhofer-AISEC for all cryptographic operations. For now, only AC17-KPABE is usable through the API. Some code from the rabe-console application was re-used as a baseline for the [encryption](src/encryption/mod.rs) module. 

## API


# License

[MIT License](https://github.com/henfur/abe-mam-poc/blob/main/LICENSE.md)


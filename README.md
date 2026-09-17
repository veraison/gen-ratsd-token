Create a [ratsd] token from provided component evidence tokens

This packages one or more evidence tokens from other attestation scheme into
a signed [ratsd] token. The component tokens as well as the associated 
collection keys and media types are specified as positional arguments. In the
order: `KEY` `MEDIATYPE` `PATH_TO_COMPONENT_TOKEN`.

Signing key is specified with the `--key` flag (gen-ratsd-token will try to
read "key.jwk" in the current directory if that is not specified).

A nonce can be specified using `--nonce` flag. If that is not specified, a
random 64 byte value will be generated.

Other top-level [ratsd] claims can also be specified using flags (see the
output of `--help` for details). They will be populated using default
values otherwise.

Example:

    gen-ratsd-token --key testdata/ec-p256.jwk --nonce 0123456789abcdef \
	    --oemid 1337 \
	    --output ratsd-token.cbor \
	    cca \
	        "application/eat-collection; profile=\"http://arm.com/CCA-SSD/1.0.0\"" \
	        testdata/cca-good.cbor \
	    eat-da \
	        "application/eat-ucs+json; eat_profile=\"tag:linaro.org,2025:device#1.0.0\"" \
	        testdata/da-spdm-good.cbor

[ratsd]: https://github.com/veraison/ratsd/tree/main/ratsd-token/v2

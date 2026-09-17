package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
	"github.com/veraison/cmw"
	"github.com/veraison/go-cose"
	token "github.com/veraison/ratsd/ratsd-token/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	rootCommand = NewRootCommand()
	rootClaims  = token.Claims{
		EatProfile: token.Profile,
	}
	debugLoggingEnabled bool
	outputPath          string
	signingKeyPath      string
)

const (
	longHelpText = `Create a ratsd token from provided component evidence tokens

This packages one or more evidence tokens from other attestation scheme into
a signed ratsd token. The component tokens as well as the associated 
collection keys and media types are specified as positional arguments. In the
order: KEY MEDIATYPE PATH_TO_COMPONENT_TOKEN.

Signing key is specified with the --key flag (gen-ratsd-token will try to
read "key.jwk" in the current directory if that is not specified).

A nonce can be specified using --nonce flag. If that is not specified, a
random 64 byte value will be generated.

Other top-level ratsd claims can also be specified using flags (see the
output of --help for details). They will be populated using default
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
`
)

type Component struct {
	Key        string
	MediaType  string
	Data       []byte
	Indicators []cmw.Indicator
}

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "gen-ratsd-token [OPTIONS] [KEY MEDIATYPE PATH]...",
		Short:   "Create a ratsd token from provided component evidence tokens",
		Long:    longHelpText,
		Version: "v0.0.1",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args)%3 != 0 {
				return errors.New("positional arguments must be specified in groups of 3 (see usage)")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, err := initLogger(debugLoggingEnabled)
			cobra.CheckErr(err)

			if rootClaims.EatNonce == nil {
				logger.Info("--nonce not specified; generating a random 64 byte value instead")
				rootClaims.EatNonce = make([]byte, 64)
				_, err = rand.Read(rootClaims.EatNonce)
				cobra.CheckErr(err)
			}
			logger.Infof("nonce: %x", rootClaims.EatNonce)

			cobra.CheckErr(rootClaims.Valid())

			// TODO: add support for reading components data from a file as  an alternative
			// to specifing them on the command line.
			if len(args) == 0 {
				logger.Fatal("no component arguments specified (see usage)")
			}

			components := make([]Component, 0, len(args)/3)
			for i := 0; i+3 < len(args); i += 3 {
				data, err := os.ReadFile(args[i+2])
				cobra.CheckErr(err)

				components = append(components, Component{
					Key:       args[i],
					MediaType: args[i+1],
					Data:      data,
					// TODO: make the indicator configurable rather than hard-coding
					// to "evidence"
					Indicators: []cmw.Indicator{cmw.Evidence},
				})
			}

			if signingKeyPath == "" {
				logger.Info("--key not specified; attempting to use key.jwk")
				signingKeyPath = "key.jwk"
			} else {
				logger.Infof("using %q as the signing key", signingKeyPath)
			}

			signer, err := createCOSESigner(signingKeyPath)
			cobra.CheckErr(err)

			ratsdEvidence, err := assembleRatsdEvidence(logger, rootClaims, components)

			outBytes, err := ratsdEvidence.Sign(signer)
			cobra.CheckErr(err)

			logger.Infof("writing output to %s", outputPath)
			cobra.CheckErr(os.WriteFile(outputPath, outBytes, 0644))

			return nil
		},
	}

	cmd.Flags().BoolVarP(
		&debugLoggingEnabled,
		"verbose", "v",
		false,
		"enable debug logging",
	)
	cmd.Flags().StringVarP(
		&outputPath,
		"output", "o",
		"ratsd-token.cbor",
		"file path into which the ratsd token will be written",
	)
	cmd.Flags().StringVarP(
		&signingKeyPath,
		"key", "k",
		"",
		"key used to sign the ratsd token",
	)

	cmd.Flags().BytesHexVarP(
		&rootClaims.EatNonce,
		"nonce", "n",
		nil,
		"nonce value that provides freshness",
	)
	cmd.Flags().Int64VarP(
		&rootClaims.OEMID,
		"oemid", "O",
		token.DefaultLeadAttesterOEMID,
		"ratsd lead attester OEMID claim value",
	)
	cmd.Flags().StringVarP(
		&rootClaims.SWName,
		"swname", "N",
		token.DefaultLeadAttesterSWName,
		"ratsd lead attester SWName claim value",
	)
	cmd.Flags().StringVarP(
		&rootClaims.SWVersion,
		"swversion", "V",
		token.DefaultLeadAttesterSWVersion,
		"ratsd lead attester SWVersion claim value",
	)

	return cmd
}

func Execute() {
	cobra.CheckErr(rootCommand.Execute())
}

func initLogger(debugLoggingEnabled bool) (*zap.SugaredLogger, error) {
	level := zap.NewAtomicLevel()
	if debugLoggingEnabled {
		level.SetLevel(zapcore.DebugLevel)
	} else {
		level.SetLevel(zapcore.InfoLevel)
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.CallerKey = zapcore.OmitKey

	zapConfig := zap.Config{
		Level:             level,
		Encoding:          "console",
		OutputPaths:       []string{"stdout"},
		ErrorOutputPaths:  []string{"stderr"},
		DisableStacktrace: true,
		EncoderConfig:     encoderConfig,
	}

	rawLogger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return rawLogger.Sugar(), nil
}

func createCOSESigner(keyFilePath string) (cose.Signer, error) {
	keyBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	return newSignerFromJWK(keyBytes)
}

func newSignerFromJWK(j []byte) (cose.Signer, error) {
	alg, key, err := getAlgAndKeyFromJWK(j)
	if err != nil {
		return nil, err
	}

	return cose.NewSigner(alg, key)
}

const noAlg = cose.Algorithm(-65537)

func getAlgAndKeyFromJWK(j []byte) (cose.Algorithm, crypto.Signer, error) {
	var (
		err error
		k   jwk.Key
		crv elliptic.Curve
		alg cose.Algorithm
	)

	k, err = jwk.ParseKey(j)
	if err != nil {
		return noAlg, nil, err
	}

	var key crypto.Signer

	err = k.Raw(&key)
	if err != nil {
		return noAlg, nil, err
	}

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		alg = ellipticCurveToAlg(v.Curve)
		if alg == noAlg {
			return noAlg, nil, fmt.Errorf("unknown elliptic curve %v", crv)
		}
	case ed25519.PrivateKey:
		alg = cose.AlgorithmEdDSA
	case *rsa.PrivateKey:
		alg = rsaJWKToAlg(k)
		if alg == noAlg {
			return noAlg, nil, fmt.Errorf("unknown RSA algorithm %q", k.Algorithm().String())
		}
	default:
		return noAlg, nil, fmt.Errorf("unknown private key type %v", reflect.TypeOf(key))
	}

	return alg, key, nil
}

func ellipticCurveToAlg(c elliptic.Curve) cose.Algorithm {
	switch c {
	case elliptic.P256():
		return cose.AlgorithmES256
	case elliptic.P384():
		return cose.AlgorithmES384
	case elliptic.P521():
		return cose.AlgorithmES512
	default:
		return noAlg
	}
}

func rsaJWKToAlg(k jwk.Key) cose.Algorithm {
	switch k.Algorithm().String() {
	case "PS256":
		return cose.AlgorithmPS256
	case "PS384":
		return cose.AlgorithmPS384
	case "PS512":
		return cose.AlgorithmPS512
	default:
		return noAlg
	}
}

func assembleRatsdEvidence(
	logger *zap.SugaredLogger,
	laClaims token.Claims,
	components []Component,
) (*token.Evidence, error) {
	if len(components) == 0 {
		return nil, errors.New("no components specified")
	}

	evidence := token.NewEvidence()
	if err := evidence.SetClaims(laClaims); err != nil {
		return nil, err
	}

	for _, c := range components {
		evidence.SetToken(c.Key, c.MediaType, c.Data, c.Indicators...)
	}

	return evidence, nil
}

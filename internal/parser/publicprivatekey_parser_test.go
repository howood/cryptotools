package parser

import (
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/howood/cryptotools/internal/entity"
)

type keyTestData struct {
	Data         string
	ResultHasErr bool
}

var privatekeyData = map[string]keyTestData{
	"privatekey1": {
		Data: `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`,
		ResultHasErr: false,
	},
	"privatekey2": {
		Data: `
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

`,
		ResultHasErr: true,
	},
	"privatekey3": {
		Data: `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
`,
		ResultHasErr: true,
	},
	"privatekey4": {
		Data: `-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAopHmB0gquCxhX46Tn+O5EfiAVUmjrCqOJLeZ0wZEaZpNDOUp
bKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HFwdV7EuT1ineHAL7h1MVwkFX2iBzP
xuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISsqURRUQYrVlirDV8JnQd3QHE87u4g
5E00fKmwuH6viFlVr/zwvAU0airh0Fk4AgikQdJxiGIzfOCapmy+LlnDb7Hu0bH9
fUK04rr57F3LU/+9QPG7FoYVFjg08dwlo8O/sGMad8K7UGHuZBIyRz5SA9nmaCT
j5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vok/4Iw4O5jDiFGadJqHpfEGhZWL00
WQ44XaHY6P62IhxyDR0nGBHLy1PwxWZKDsFK6BwpJ3VX6bb1ZkbhDMr26gCp
-----END RSA PRIVATE KEY-----
`,
		ResultHasErr: true,
	},
	"privatekey5": {
		Data: `-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,32242D3525AEDC64
MOZ0m/BCLFNS+ujlcnQR3gOIb5w5hwu1jByw8/kyvTMIHqAx1ANgqV1gFBGX7F0
vdfmNQKnjLcH8cGueUYnmx4vSu9FnKK91abNW9Nd67MDtJEztHckahXDYy7oX1t
LNh3QtaZ32AgHro7QxxCGIHQeDaiGePg7WhVqH8EXo3c+/L/5sQpfx0eG30nrDjl
+cmXgmzU2uQsPL2ckP9NQTgRU4QgWYDBle0YhUXTAG8eW9XG9iCm9iFO4WLWtWd24
Q799A1w6UJReHKQq+vdrN76PgK32NMNmindOqzKVzFL4TsjLyGyWofImpG65oO
FSc4GXTsRkZ0OQxixakpKShRpJ5pW6V1PN4tR/RCRWmpW/yZTr4qtQzcw+AY6ONA
QEVtJQeN69LJncuy9MY/K2F7hn5lCYy/TOnM1OOD6/a1R6U4xoH6qkasLGchiTIP
/NIfrITQho49I7cIJ9HmW54Bmeqh2U9WiSD4aSyxL1Mm6vGoc81U2XjJmcUmQ9XHmhx
R4iWaATaz6RTsxBksNhn7jVx34DDvRDJ4MSjLaNpjnvAdYTM7YislsBulDTr8ZF6P9
Fa7VyFP4TyCjUM1w==
-----END DSA PRIVATE KEY-----
`,
		ResultHasErr: true,
	},
	"privatekey6": {
		Data: `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,32242D3525AEDC64
MOZ0m/BCLFNS+ujlcnQR3gOIb5w5hwu1jByw8/kyvTMIHqAx1ANgqV1gFBGX7F0
vdfmNQKnjLcH8cGueUYnmx4vSu9FnKK91abNW9Nd67MDtJEztHckahXDYy7oX1t
LNh3QtaZ32AgHro7QxxCGIHQeDaiGePg7WhVqH8EXo3c+/L/5sQpfx0eG30nrDjl
+cmXgmzU2uQsPL2ckP9NQTgRU4QgWYDBle0YhUXTAG8eW9XG9iCm9iFO4WLWtWd24
Q799A1w6UJReHKQq+vdrN76PgK32NMNmindOqzKVzFL4TsjLyGyWofImpG65oO
FSc4GXTsRkZ0OQxixakpKShRpJ5pW6V1PN4tR/RCRWmpW/yZTr4qtQzcw+AY6ONA
QEVtJQeN69LJncuy9MY/K2F7hn5lCYy/TOnM1OOD6/a1R6U4xoH6qkasLGchiTIP
/NIfrITQho49I7cIJ9HmW54Bmeqh2U9WiSD4aSyxL1Mm6vGoc81U2XjJmcUmQ9XHmhx
R4iWaATaz6RTsxBksNhn7jVx34DDvRDJ4MSjLaNpjnvAdYTM7YislsBulDTr8ZF6P9
Fa7VyFP4TyCjUM1w==
-----END RSA PRIVATE KEY-----
`,
		ResultHasErr: true,
	},
}

var publickeyData = map[string]keyTestData{
	"publickey1": {
		Data: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END PUBLIC KEY-----`,
		ResultHasErr: false,
	},

	"publickey2": {
		Data: `
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
	`,
		ResultHasErr: true,
	},
	"publickey3": {
		Data: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END PUBLIC KEY-----`,
		ResultHasErr: true,
	},
	"publickey4": {
		Data: `-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END RSA PUBLIC KEY-----`,
		ResultHasErr: true,
	},
	"publickey5": {
		Data: `-----BEGIN PUBLIC-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END PUBLIC-----`,
		ResultHasErr: true,
	},
	"publickey6": {
		Data: `-----BEGIN RSA PUBLIC KEY-----
AAAAB3NzaC1kc3MAAACBAIHozHi6CHwvGDt7uEYkEmn4STOj2neOo5mPOZFpBjs
KzzWBqBuAxoMwMgHy3zZAIgmzMwIVQum4/uIHlhOx0Q4QDLJbveFShuXxBjm5BOU1
rCCSeqYCOPdub9hx3uzZaTNqfFIvO4/NTcjp7pgQqBdvWs0loyYViYVWpVQmMdif
AAAAFQDhaD9m//n07C+R+X46g5iTYFA9/QAAAIBVbBXXL3/+cHfbyKgCCe2CqjRESQ
i2nwiCPwyVzzwfHw4MyoYe5Nk8sfTiweY8Lus7YXXUZCPbnCMkashsbFVO9w
/q3xmbrKfBTS+QOjs6nebftnxwk/RrwPmb9MS/kdWMEigdCoum9MmyJlOw5fwGl
P1ufVHn+v9uTKWpPgr0egAAAIArKV4Yr3mFciTbzcGCicW+axekoCKq520Y68mQ
1xrI4HJVnTOb6J1SqvyK68eC2I5lo1kJ6aUixJt/D3d/GHnA+i5McbJgLsNuiDs
RI3Q6v3ygKeQaPtgITKS7UY4S0FBQlw9q7qjHVphSOPvo2VUHkG6hYiyaLvLrX
Jo7JPk6tQ==
-----END RSA PUBLIC KEY-----`,
		ResultHasErr: true,
	},
}

func Test_ConvertPublicKey(t *testing.T) {
	publickeyStr := `{
      "kid": "7c309e3a1c1999cb0404ab7125ee40b7cdbcaf7d",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "3MdFK4pXPvehMipDL_COfqn6o9soHgSaq_V1o8U_5gTZ-j9DxO9PV7BVncXBgHFctnp3JQ1QTDF7txeHeuLOS4KziRw5r4ohaj2WoOTqXh7lqVMR2YDAcBK46asS177NpkQ1CqHIsy3kNfqhXLwTaKfdlwdA_XUfRbKORWbq0kDxV35egx35nHl5qJ6aP6fcpsnnPvHf7KWO0zkdvwuR-IX79HjqUAEg5UERd5FK4y06PRbxuXHjAgVhHu_sk4reNXNp1HRuTYtQ26DFbVaIjsWb8-nQC8-7FkTjlw9FteAwLVGOm9sTLFp73jAf0pWLh7sJ02pBxZKjsxLO1Lvg7w",
      "use": "sig"
    }`
	jwk, err := ConvertToJSONWebKey([]byte(publickeyStr))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := ConvertToRSAPublicFromJWK(&jwk)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if _, err := ConvertToRSAPrivateFromJWK(&jwk); err == nil {
		t.Fatal("no error to convert private key")
	} else {
		t.Logf("failed test %#v", err)
	}
	//t.Log(publickey)
	pempublickey, err := DecodePublicKey(publickey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if _, err := DecodePublicKey(&rsa.PublicKey{}); err == nil {
		t.Fatal("no error to decode public key")
	} else {
		t.Logf("failed test %#v", err)
	}
	//t.Log(fmt.Sprintf("%v", string(pempublickey)))
	rsakey := &entity.RsaKey{}
	err = ReadPublicKey(pempublickey, rsakey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	//t.Log(rsakey.PublicKey)
	if reflect.DeepEqual(rsakey.PublicKey, publickey) == false {
		t.Fatalf("failed compare publickey ")
	}
	t.Log("success PublicKeyConvertTest")
}

func Test_ReadPrivatePublicKey(t *testing.T) {
	for k, v := range privatekeyData {
		rsakey := &entity.RsaKey{}
		err := ReadPrivateKey([]byte(v.Data), rsakey)
		if (err != nil) != v.ResultHasErr {
			t.Fatalf("failed test :%s %#v", k, err)
		} else {
			t.Logf("failed test :%s %#v", k, err)
		}
		t.Logf("success : %s", k)

	}
	for k, v := range publickeyData {
		rsakey := &entity.RsaKey{}
		err := ReadPublicKey([]byte(v.Data), rsakey)
		if (err != nil) != v.ResultHasErr {
			t.Fatalf("failed test :%s %#v", k, err)
		} else {
			t.Logf("failed test :%s %#v", k, err)
		}
		t.Logf("success : %s", k)

	}
}

func Test_ConvertPrivatecKey(t *testing.T) {
	privatekeyStr := `{
    "kty":"RSA",
    "kid":"juliet@capulet.lit",
    "use":"enc",
    "n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q",
    "e":"AQAB",
    "d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
    "p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws",
    "q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s",
    "dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c",
    "dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots",
    "qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"
    }`
	jwk, err := ConvertToJSONWebKey([]byte(privatekeyStr))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	privatekey, err := ConvertToRSAPrivateFromJWK(&jwk)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if _, err := ConvertToRSAPublicFromJWK(&jwk); err == nil {
		t.Fatal("no error to convert public key")
	} else {
		t.Logf("failed test %#v", err)
	}
	//t.Log(privatekey)

	pemprikey1 := DecodePrivateKeyPKCS1(privatekey)
	//t.Log(fmt.Sprintf("%v", string(pemprikey1)))
	rsakey := &entity.RsaKey{}
	err = ReadPrivateKey(pemprikey1, rsakey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	pemprikeyagain1 := DecodePrivateKeyPKCS1(rsakey.PrivateKey)
	if reflect.DeepEqual(pemprikeyagain1, pemprikey1) == false {
		t.Fatalf("failed compare privatekey PKCS#1")
	}

	pemprikey2, err := DecodePrivateKeyPKCS8(privatekey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	//t.Log(fmt.Sprintf("%v", string(pemprikey2)))
	rsakey = &entity.RsaKey{}
	err = ReadPrivateKey(pemprikey2, rsakey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	pemprikeyagain2, err := DecodePrivateKeyPKCS8(rsakey.PrivateKey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual(pemprikeyagain2, pemprikey2) == false {
		t.Fatalf("failed compare privatekey PKCS#8")
	}

	t.Log("success PrivateKeyConvertTest")
}

func Test_ConvertPublicKeyJWKprivateKey(t *testing.T) {
	privatekey := `-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAopHmB0gquCxhX46Tn+O5EfiAVUmjrCqOJLeZ0wZEaZpNDOUp
bKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HFwdV7EuT1ineHAL7h1MVwkFX2iBzP
xuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISsqURRUQYrVlirDV8JnQd3QHE87u4g
5E00fKmwuH6viFlVr/zwvAU0airh0Fk4AgikQdJxiGIzfOCapmy+LlnDb7Hu0bH9
fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O/sGMad8K7UGHuZBIyRz5SA9nmaCT
j5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vok/4Iw4O5jDiFGadJqHpfEGhZWL00
37gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82quns/9c1ARiYssmt3YP5dkVilSfX0U
7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9nwzE573YHTXWdzgrN3KqGoRcaBCR
caq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pfnSrR7ChAEk1ZR567L+malLKARkI3
lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6btwv7AzaptOn66KJ7tEo92yJbMdZ
vOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9zSflwh6m3w5TyQziTOp9O468CAwEA
AQKCAgAvuA3CU2+esgA/EVXJ2AlJ+hyJbF0ruy4QHwh7Bdrs+IrnXxjit8iJRQw8
TdpRplvzRwd0MqbLss+vVrJWCWm39Nb0e9qLM3ygPmeBkhbxdxovZ+2hYXHvfSsx
kVAV/g7HbJ+se/6sTmdbr0GVCfS4lsIbu2jbJpnHCf+DZV6evt5479Md0H+4nAKw
lRcnObnKN7/eINT62O2Bv76N8kVswL3sn46neDJM6ZyFdHnGfn8wdEOJEhyQdPvJ
Ytq9JFNEDfCxseSYFaKg52jn+MQZCW0S4pKNg++4C18iEWwmt8bcNGM8A04+nYRz
o4QVMSi9aBX93cDK5fjL/kgYJ/KDjmCD8TmdC9WIT1KDE9slMnjS/avqgX8OarFG
lTB0VBPCxU2myVj7MHFG2oLOVw5BYCT2nwQnAXL7O9bh0lRGZ3c4o7nW3/U7t7sS
LfIPQUN3qgpXdNpDHTFvBvuSIavreKIdJbu0JjjUBZlHdn/wuBpXLRKf9//VEnrJ
r1rtZXcgMX9ddyAnuKcXCQrt9Xi31gPMraE8Fpmd7apymLQyMApn0z+e7kChJc5+
roQXad9v4zjr+GMV49QChetjN3aTLoOHtM3MF2aXSVEGALDPuZ6xLQfZ2/raWl1n
o0GuE9nb/tlOnpdaVIWVRcnl9MyyNIlAwRRR+KHgx50BnY9p8QKCAQEA1sTwE6s/
D59PP5xFaVGDRYfBhc3jQsaME3iTtJRpCae0v999EvsBj3QKSKTvqRnghjfnFDLQ
QAOV/3rWdkzXihSw5oAYK+VUKHT+5MKSECapbxD4g9WC2yeQrUMEzHLrPaM6qJ0s
ebyjOTeov4iExhreUsqZL4ghg26Zmgmhrg7Qyn7tBDIek39V7D1w1wOTiJU5WH5z
fsjIxDsSxPxdaSenlzJypMrg4hlgfvGnC+yqPd4eQRV5d6zVurqaYEW150ImO/SF
nlkIfdmOI6fwUCCqBN3q2Xl1KkehQGLC7AJN1t8vOM2ivT3BFGcbYaU6KZluMMce
1DwflwZ7AJ1MSQKCAQEAwceRWu3d8QLMq1KYu0uT5sLF6BAmsQfSHmZq6q3PoeFM
obEkeX+9atbihrIjZ1jTjGzlJI7WY7aM7cYNs9/RnLsyNNfm1/jVLVmzDCTrSaAZ
HjCVlcHHVV05MsHsgyeI8AwHBLDVsc0Q7RamIzQDXxC4w+M6+fwIzUWKDyc7ar6/
kjw0Q9h9TtgHLuR1gxwyUaMlKKcg5ElYeGrzfOrUa6inbdobe64YyekZ3pewUbgn
3OYxKIfHsfpZwR/Eoonle6xIXCg+Y60mWS8Fzahpun++8a+JJlOEJ1nqCrQY2PPH
mpMFv0UmRoX2EpKW1oe+bqlRM1pmKtehEBKv9meANwKCAQEAo/mG5y2HHzFd+04f
/NI8bLjCu5s/mXsn9bHI7EWnkLSXnytOPlCgl1tcgqxTQwO71h4Wcuh88XMLchzi
Yz42DnnPup0wV0tnnt/8wMIBbQ1nraICa/13REYIAxE5N7PCAbR/k7809tlcsdHa
KCpeXTakage/P3grRkMKSX5zEAbFyOVxpxNxHuJIwu8CGVfkq5JrTzJ0kedQyenk
YbvgwemB3kGpIEK5wkbn0uRDyyntrQDKjpyLuiCeqkvQlBKFWMS7lmkSH50Qi62w
BW8yXqshxEd/CH3gQ+CesB73feQgdB7A2hi+2MeuhBpY4IubRamcZOeSlS42XEOZ
ZBW06QKCAQEAtATFCTcfTu3t217RGnY8wUzCdDLE7wM39RvqSXgNAvL9sNyS6Ph9
rIpSSRWmhDTl2nezbAHyMxH83Et4oVjVLwhMvQCxqIO27vl8t1R47J35l61E2an6
l1gScg/ru2/37CEQSBBLhXDfP5Ih52RDmYY8T2aCfIfiWWg3uJoWvbTU3XJmj3zH
9H4GNk7wyEtih6rLM3gHu2xT7xJUfwDdM+KrIAdWLtDuoGyXps0+dLxi8/k5Q9DX
+IR960aq8uCuOvUzB8IvK4RIsuNXPdYt2p8gcQBEpkFB7Ri/rw/eYXYfQX9CAI2p
4CxFDL33uPbEN6O+FrntXfGR5A+oPn2qgwKCAQBWXHHsrnJ+q0GdbNjOR9qMpgsD
tsrEL2s1628vl7M9nBt9UM9J0vQ7IuMvwymrbTR0E+z6tx7Z6/J+GVhhWwCvKaCp
n9hs5ts+cp7fw1VCwmduxQoQCo+4RyFdmCGtcwZgM6F0KrEanp2812/ZylWROSik
ny2TtaLU7m5DKUuKDliAvHs5S4ug/EcA+Y3NnBS7lXmeoBJUtaauTtdOKnrvqhGv
Z5HK0Mz2B7HUWHaqtlUCEpiqUlh7aGybuP+Wyhl5KePuY2rpkyfvz4X/nYI7DTo3
WQ44XaHY6P62IhxyDR0nGBHLy1PwxWZKDsFK6BwpJ3VX6bb1ZkbhDMr26gCp
-----END RSA PRIVATE KEY-----`

	checkdata := `{"kty":"RSA","kid":"aaaa","n":"opHmB0gquCxhX46Tn-O5EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb_MEJUiXfzoRH6Q23H3inzl02XQE1HFwdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl_yDg8aSWIWT0E-dlbAGXqzz6uISsqURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr_zwvAU0airh0Fk4AgikQdJxiGIzfOCapmy-LlnDb7Hu0bH9fUK04rr57F3LU_-9QPG7FoLYVFjg08dwlo8O_sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs_OWSFkIuDhPix-5vok_4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82quns_9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48-V7t-GN09PdFdN-iXJQlg9nwzE573YHTXWdzgrN3KqGoRcaBCRcaq-nRW8RcHReIkxgAdXzQl2sSJLphZNH4pfnSrR7ChAEk1ZR567L-malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9zSflwh6m3w5TyQziTOp9O468","e":"AQAB","d":"L7gNwlNvnrIAPxFVydgJSfociWxdK7suEB8IewXa7PiK518Y4rfIiUUMPE3aUaZb80cHdDKmy7LPr1ayVglpt_TW9HvaizN8oD5ngZIW8XcaL2ftoWFx730rMZFQFf4Ox2yfrHv-rE5nW69BlQn0uJbCG7to2yaZxwn_g2Venr7eeO_THdB_uJwCsJUXJzm5yje_3iDU-tjtgb--jfJFbMC97J-Op3gyTOmchXR5xn5_MHRDiRIckHT7yWLavSRTRA3wsbHkmBWioOdo5_jEGQltEuKSjYPvuAtfIhFsJrfG3DRjPANOPp2Ec6OEFTEovWgV_d3AyuX4y_5IGCfyg45gg_E5nQvViE9SgxPbJTJ40v2r6oF_DmqxRpUwdFQTwsVNpslY-zBxRtqCzlcOQWAk9p8EJwFy-zvW4dJURmd3OKO51t_1O7e7Ei3yD0FDd6oKV3TaQx0xbwb7kiGr63iiHSW7tCY41AWZR3Z_8LgaVy0Sn_f_1RJ6ya9a7WV3IDF_XXcgJ7inFwkK7fV4t9YDzK2hPBaZne2qcpi0MjAKZ9M_nu5AoSXOfq6EF2nfb-M46_hjFePUAoXrYzd2ky6Dh7TNzBdml0lRBgCwz7mesS0H2dv62lpdZ6NBrhPZ2_7ZTp6XWlSFlUXJ5fTMsjSJQMEUUfih4MedAZ2PafE","p":"1sTwE6s_D59PP5xFaVGDRYfBhc3jQsaME3iTtJRpCae0v999EvsBj3QKSKTvqRnghjfnFDLQQAOV_3rWdkzXihSw5oAYK-VUKHT-5MKSECapbxD4g9WC2yeQrUMEzHLrPaM6qJ0sebyjOTeov4iExhreUsqZL4ghg26Zmgmhrg7Qyn7tBDIek39V7D1w1wOTiJU5WH5zfsjIxDsSxPxdaSenlzJypMrg4hlgfvGnC-yqPd4eQRV5d6zVurqaYEW150ImO_SFnlkIfdmOI6fwUCCqBN3q2Xl1KkehQGLC7AJN1t8vOM2ivT3BFGcbYaU6KZluMMce1DwflwZ7AJ1MSQ","q":"wceRWu3d8QLMq1KYu0uT5sLF6BAmsQfSHmZq6q3PoeFMobEkeX-9atbihrIjZ1jTjGzlJI7WY7aM7cYNs9_RnLsyNNfm1_jVLVmzDCTrSaAZHjCVlcHHVV05MsHsgyeI8AwHBLDVsc0Q7RamIzQDXxC4w-M6-fwIzUWKDyc7ar6_kjw0Q9h9TtgHLuR1gxwyUaMlKKcg5ElYeGrzfOrUa6inbdobe64YyekZ3pewUbgn3OYxKIfHsfpZwR_Eoonle6xIXCg-Y60mWS8Fzahpun--8a-JJlOEJ1nqCrQY2PPHmpMFv0UmRoX2EpKW1oe-bqlRM1pmKtehEBKv9meANw","dp":"o_mG5y2HHzFd-04f_NI8bLjCu5s_mXsn9bHI7EWnkLSXnytOPlCgl1tcgqxTQwO71h4Wcuh88XMLchziYz42DnnPup0wV0tnnt_8wMIBbQ1nraICa_13REYIAxE5N7PCAbR_k7809tlcsdHaKCpeXTakage_P3grRkMKSX5zEAbFyOVxpxNxHuJIwu8CGVfkq5JrTzJ0kedQyenkYbvgwemB3kGpIEK5wkbn0uRDyyntrQDKjpyLuiCeqkvQlBKFWMS7lmkSH50Qi62wBW8yXqshxEd_CH3gQ-CesB73feQgdB7A2hi-2MeuhBpY4IubRamcZOeSlS42XEOZZBW06Q","dq":"tATFCTcfTu3t217RGnY8wUzCdDLE7wM39RvqSXgNAvL9sNyS6Ph9rIpSSRWmhDTl2nezbAHyMxH83Et4oVjVLwhMvQCxqIO27vl8t1R47J35l61E2an6l1gScg_ru2_37CEQSBBLhXDfP5Ih52RDmYY8T2aCfIfiWWg3uJoWvbTU3XJmj3zH9H4GNk7wyEtih6rLM3gHu2xT7xJUfwDdM-KrIAdWLtDuoGyXps0-dLxi8_k5Q9DX-IR960aq8uCuOvUzB8IvK4RIsuNXPdYt2p8gcQBEpkFB7Ri_rw_eYXYfQX9CAI2p4CxFDL33uPbEN6O-FrntXfGR5A-oPn2qgw","qi":"Vlxx7K5yfqtBnWzYzkfajKYLA7bKxC9rNetvL5ezPZwbfVDPSdL0OyLjL8Mpq200dBPs-rce2evyfhlYYVsArymgqZ_YbObbPnKe38NVQsJnbsUKEAqPuEchXZghrXMGYDOhdCqxGp6dvNdv2cpVkTkopJ8tk7Wi1O5uQylLig5YgLx7OUuLoPxHAPmNzZwUu5V5nqASVLWmrk7XTip676oRr2eRytDM9gex1Fh2qrZVAhKYqlJYe2hsm7j_lsoZeSnj7mNq6ZMn78-F_52COw06N1kOOF2h2Oj-tiIccg0dJxgRy8tT8MVmSg7BSugcKSd1V-m29WZG4QzK9uoAqQ"}`

	rsakey := &entity.RsaKey{}
	err := ReadPrivateKey([]byte(privatekey), rsakey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	jwk, err := GenerateJSONWebKeyWithRSAPrivateKey(rsakey.PrivateKey, "aaaa")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(jwk))
	if reflect.DeepEqual(jwk, []byte(checkdata)) == false {
		t.Fatalf("failed compare ConvertPublicKeyJWKPrivateKey")
	}
	kid := GenerateHashFromRsaKey(rsakey.PrivateKey)
	t.Log(kid)

	t.Log("success ConvertPublicKeyJWKPrivateKey")

}

func Test_ConvertPublicKeyJWKPublicKey(t *testing.T) {
	publickey := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END PUBLIC KEY-----`

	checkdata := `{"kty":"RSA","kid":"aaaa","n":"opHmB0gquCxhX46Tn-O5EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb_MEJUiXfzoRH6Q23H3inzl02XQE1HFwdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl_yDg8aSWIWT0E-dlbAGXqzz6uISsqURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr_zwvAU0airh0Fk4AgikQdJxiGIzfOCapmy-LlnDb7Hu0bH9fUK04rr57F3LU_-9QPG7FoLYVFjg08dwlo8O_sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs_OWSFkIuDhPix-5vok_4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82quns_9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48-V7t-GN09PdFdN-iXJQlg9nwzE573YHTXWdzgrN3KqGoRcaBCRcaq-nRW8RcHReIkxgAdXzQl2sSJLphZNH4pfnSrR7ChAEk1ZR567L-malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9zSflwh6m3w5TyQziTOp9O468","e":"AQAB"}`

	rsakey := &entity.RsaKey{}
	err := ReadPublicKey([]byte(publickey), rsakey)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	jwk, err := GenerateJSONWebKeyWithRSAPublicKey(rsakey.PublicKey, "aaaa")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(jwk))
	if reflect.DeepEqual(jwk, []byte(checkdata)) == false {
		t.Fatalf("failed compare ConvertPublicKeyJWKPublicKey")
	}
	kid := GenerateHashFromRsaKey(rsakey.PublicKey)
	t.Log(kid)
	t.Log("success ConvertPublicKeyJWKPublicKey")

}

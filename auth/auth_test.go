/*-
 * Copyright 2015 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/stretchr/testify/assert"
)

var fakeChains = [][]*x509.Certificate{
	{
		{
			Subject: pkix.Name{
				CommonName:         "gopher",
				OrganizationalUnit: []string{"triangle", "circle"},
			},
			DNSNames:    []string{"circle"},
			IPAddresses: []net.IP{net.IPv4(192, 168, 99, 100)},
			Extensions: []pkix.Extension{
				{
					Id:       uri.OidExtensionSubjectAltName,
					Value:    getURISANFromString("scheme://valid/path"),
					Critical: false,
				},
			},
		},
	},
}

func getURISANFromString(s string) (uriSAN []byte) {
	uriSAN, err := uri.MarshalUriSANs([]string{s})
	if err != nil {
		panic(err)
	}

	return uriSAN
}

func TestAuthorizeNotVerified(t *testing.T) {
	testACL := Acl{
		AllowAll: true,
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, nil), "conn w/o cert should be rejected")
}

func TestAuthorizeReject(t *testing.T) {
	testACL := Acl{
		AllowedCNs:  []string{"test"},
		AllowedOUs:  []string{"test"},
		AllowedDNSs: []string{"test"},
		AllowedURIs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "should reject cert w/o matching CN/OU")
}

func TestAuthorizeAllowAll(t *testing.T) {
	testACL := Acl{
		AllowAll: true,
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-all should always allow authed clients")
}

func TestAuthorizeAllowCN(t *testing.T) {
	testACL := Acl{
		AllowedCNs: []string{"gopher"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-cn should allow clients with matching CN")
}

func TestAuthorizeAllowOU(t *testing.T) {
	testACL := Acl{
		AllowedOUs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-ou should allow clients with matching OU")
}

func TestAuthorizeAllowDNS(t *testing.T) {
	testACL := Acl{
		AllowedDNSs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-dns-san should allow clients with matching DNS SAN")
}

func TestAuthorizeAllowIP(t *testing.T) {
	testACL := Acl{
		AllowedIPs: []net.IP{net.IPv4(192, 168, 99, 100)},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-ip-san should allow clients with matching IP SAN")
}

func TestAuthorizeAllowURI(t *testing.T) {
	testACL := Acl{
		AllowedURIs: []string{"scheme://valid/path"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-uri-san should allow clients with matching URI SAN")
}

func TestAuthorizeRejectURI(t *testing.T) {
	testACL := Acl{
		AllowedURIs: []string{"schema://invalid/path"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "should reject cert w/o matching URI")
}

func TestVerifyAllowEmpty(t *testing.T) {
	testACL := Acl{}

	// For VerifyPeerCertificateClient, we perform hostname verification
	// and skip ACLs if the ACL is empty (i.e. no flag has been set to verify
	// any attributes of the server peer certificate).
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "empty client ACL skips extra checks")
}

func TestVerifyAllowCN(t *testing.T) {
	testACL := Acl{
		AllowedCNs: []string{"gopher"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-cn should allow servers with matching CN")
}

func TestVerifyAllowOU(t *testing.T) {
	testACL := Acl{
		AllowedOUs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-ou should allow servers with matching OU")
}

func TestVerifyAllowDNS(t *testing.T) {
	testACL := Acl{
		AllowedDNSs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-dns-san should allow servers with matching DNS SAN")
}

func TestVerifyAllowIP(t *testing.T) {
	testACL := Acl{
		AllowedIPs: []net.IP{net.IPv4(192, 168, 99, 100)},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-ip-san should allow servers with matching IP SAN")
}

func TestVerifyRejectCN(t *testing.T) {
	testACL := Acl{
		AllowedCNs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching CN")
}

func TestVerifyRejectOU(t *testing.T) {
	testACL := Acl{
		AllowedOUs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching OU")
}

func TestVerifyRejectDNS(t *testing.T) {
	testACL := Acl{
		AllowedDNSs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching DNS SAN")
}

func TestVerifyRejectIP(t *testing.T) {
	testACL := Acl{
		AllowedIPs: []net.IP{net.IPv4(1, 1, 1, 1)},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching IP SAN")
}

func TestVerifyAllowURI(t *testing.T) {
	testACL := Acl{
		AllowedURIs: []string{"scheme://valid/path"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-uri-san should allow clients with matching URI SAN")
}

func TestVerifyRejectURI(t *testing.T) {
	testACL := Acl{
		AllowedURIs: []string{"scheme://invalid/path"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching URI")
}

func TestVerifyNoVerifiedChains(t *testing.T) {
	testACL := Acl{}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, nil), "should reject if no verified chains")
}

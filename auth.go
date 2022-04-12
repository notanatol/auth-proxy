// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"golang.org/x/crypto/bcrypt"
)

type authRecord struct {
	Role   string    `json:"r"`
	Expiry time.Time `json:"e"`
}

type authenticator struct {
	passwordHash []byte
	ciph         *encrypter
	enforcer     *casbin.Enforcer
}

func newAuthenticator(encryptionKey, passwordHash string) (*authenticator, error) {
	m, err := model.NewModelFromString(`
	[request_definition]
	r = sub, obj, act

	[role_definition]
	g = _, _

	[policy_definition]
	p = sub, obj, act

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = (g(r.sub, p.sub) || r.sub == p.sub) && (keyMatch(r.obj, p.obj) || keyMatch(r.obj, '/v1'+p.obj)) && regexMatch(r.act, p.act)`)

	if err != nil {
		return nil, err
	}

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}

	if err := applyPolicies(e); err != nil {
		return nil, err
	}

	ciph, err := newEncrypter([]byte(encryptionKey))
	if err != nil {
		return nil, err
	}

	auth := authenticator{
		enforcer:     e,
		ciph:         ciph,
		passwordHash: []byte(passwordHash),
	}

	return &auth, nil
}

func (a *authenticator) Authorize(password string) bool {
	return nil == bcrypt.CompareHashAndPassword(a.passwordHash, []byte(password))
}

var (
	errInvalidExpiry = errors.New("expiry duration must be a positive number")
	errTokenExpired  = errors.New("token expired")
)

func (a *authenticator) GenerateKey(role string, expiryDuration int) (string, error) {
	if expiryDuration == 0 {
		return "", errInvalidExpiry
	}

	ar := authRecord{
		Role:   role,
		Expiry: time.Now().Add(time.Second * time.Duration(expiryDuration)),
	}

	data, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}

	encryptedBytes, err := a.ciph.encrypt(data)
	if err != nil {
		return "", err
	}

	apiKey := base64.StdEncoding.EncodeToString(encryptedBytes)

	return apiKey, nil
}

func (a *authenticator) RefreshKey(apiKey string, expiryDuration int) (string, error) {
	if expiryDuration == 0 {
		return "", errInvalidExpiry
	}

	decoded, err := base64.StdEncoding.DecodeString(apiKey)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := a.ciph.decrypt(decoded)
	if err != nil {
		return "", err
	}

	var ar authRecord
	if err := json.Unmarshal(decryptedBytes, &ar); err != nil {
		return "", err
	}

	if time.Now().After(ar.Expiry) {
		return "", errTokenExpired
	}

	ar.Expiry = time.Now().Add(time.Duration(expiryDuration) * time.Second)

	data, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}

	encryptedBytes, err := a.ciph.encrypt(data)
	if err != nil {
		return "", err
	}

	apiKey = base64.StdEncoding.EncodeToString(encryptedBytes)

	return apiKey, nil
}

func (a *authenticator) Enforce(apiKey, obj, act string) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(apiKey)
	if err != nil {
		log.Println("decode token", err)
		return false, err
	}

	decryptedBytes, err := a.ciph.decrypt(decoded)
	if err != nil {
		log.Println("decrypt token", err)
		return false, err
	}

	var ar authRecord
	if err := json.Unmarshal(decryptedBytes, &ar); err != nil {
		log.Println("unmarshal token", err)
		return false, err
	}

	if time.Now().After(ar.Expiry) {
		log.Println("token expired")
		return false, errTokenExpired
	}

	allow, err := a.enforcer.Enforce(ar.Role, obj, act)
	if err != nil {
		log.Println("enforce", err)
		return false, err
	}

	return allow, nil
}

type encrypter struct {
	gcm cipher.AEAD
}

func newEncrypter(key []byte) (*encrypter, error) {
	hasher := md5.New()
	_, err := hasher.Write(key)
	if err != nil {
		return nil, err
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	block, err := aes.NewCipher([]byte(hash))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &encrypter{
		gcm: gcm,
	}, nil
}

func (e encrypter) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := e.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (e encrypter) decrypt(data []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func applyPolicies(e *casbin.Enforcer) error {
	_, err := e.AddPolicies([][]string{
		{"consumer", "/bytes/*", "GET"},
		{"creator", "/bytes", "POST"},
		{"consumer", "/chunks/*", "GET"},
		{"creator", "/chunks", "POST"},
		{"consumer", "/bzz/*", "GET"},
		{"creator", "/bzz/*", "PATCH"},
		{"creator", "/bzz", "POST"},
		{"creator", "/bzz?*", "POST"},
		{"consumer", "/bzz/*/*", "GET"},
		{"creator", "/tags", "GET"},
		{"creator", "/tags?*", "GET"},
		{"creator", "/tags", "POST"},
		{"creator", "/tags/*", "(GET)|(DELETE)|(PATCH)"},
		{"creator", "/pins/*", "(GET)|(DELETE)|(POST)"},
		{"maintainer", "/pins", "GET"},
		{"creator", "/pss/send/*", "POST"},
		{"consumer", "/pss/subscribe/*", "GET"},
		{"creator", "/soc/*/*", "POST"},
		{"creator", "/feeds/*/*", "POST"},
		{"consumer", "/feeds/*/*", "GET"},
		{"maintainer", "/stamps", "GET"},
		{"maintainer", "/stamps/*", "GET"},
		{"maintainer", "/stamps/*/*", "POST"},
		{"maintainer", "/stamps/topup/*/*", "PATCH"},
		{"maintainer", "/stamps/dilute/*/*", "PATCH"},
		{"maintainer", "/addresses", "GET"},
		{"maintainer", "/blocklist", "GET"},
		{"maintainer", "/connect/*", "POST"},
		{"maintainer", "/peers", "GET"},
		{"maintainer", "/peers/*", "DELETE"},
		{"maintainer", "/pingpong/*", "POST"},
		{"maintainer", "/topology", "GET"},
		{"maintainer", "/welcome-message", "(GET)|(POST)"},
		{"maintainer", "/balances", "GET"},
		{"maintainer", "/balances/*", "GET"},
		{"maintainer", "/chequebook/cashout/*", "GET"},
		{"accountant", "/chequebook/cashout/*", "POST"},
		{"accountant", "/chequebook/withdraw", "POST"},
		{"accountant", "/chequebook/withdraw?*", "POST"},
		{"accountant", "/chequebook/deposit", "POST"},
		{"accountant", "/chequebook/deposit?*", "POST"},
		{"maintainer", "/chequebook/cheque/*", "GET"},
		{"maintainer", "/chequebook/cheque", "GET"},
		{"maintainer", "/chequebook/address", "GET"},
		{"maintainer", "/chequebook/balance", "GET"},
		{"maintainer", "/chunks/*", "(GET)|(DELETE)"},
		{"maintainer", "/reservestate", "GET"},
		{"maintainer", "/chainstate", "GET"},
		{"maintainer", "/settlements/*", "GET"},
		{"maintainer", "/settlements", "GET"},
		{"maintainer", "/transactions", "GET"},
		{"consumer", "/transactions/*", "GET"},
		{"accountant", "/transactions/*", "(POST)|(DELETE)"},
		{"consumer", "/consumed", "GET"},
		{"consumer", "/consumed/*", "GET"},
		{"consumer", "/chunks/stream", "GET"},
		{"creator", "/stewardship/*", "GET"},
		{"consumer", "/stewardship/*", "PUT"},
	})

	if err != nil {
		return err
	}

	// consumer > creator > accountant > maintainer
	_, err = e.AddGroupingPolicies([][]string{
		{"creator", "consumer"},
		{"accountant", "creator"},
		{"maintainer", "accountant"},
	})

	return err
}

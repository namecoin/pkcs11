package p11

import "github.com/miekg/pkcs11"

// SecretKey is an Object representing a secret (symmetric) key. Since the
// SecretKey method can be called on any object, it is the user's
// responsibility to ensure that the object is actually a secret key. For
// instance, if you use a FindObjects template that includes CKA_CLASS:
// CKO_SECRET_KEY, you can be confident the resulting object is a secret key.
type SecretKey interface {
	Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error)
	Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error)
	Object() Object
}

// secretKeyImpl is an Object representing a secret (symmetric) key. Since the
// SecretKey method can be called on any object, it is the user's
// responsibility to ensure that the object is actually a secret key. For
// instance, if you use a FindObjects template that includes CKA_CLASS:
// CKO_SECRET_KEY, you can be confident the resulting object is a secret key.
type secretKeyImpl objectImpl

// Encrypt encrypts a plaintext with a given mechanism.
func (secret secretKeyImpl) Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	s := secret.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.EncryptInit(s.handle, &mechanism, secret.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Decrypt decrypts the input with a given mechanism.
func (secret secretKeyImpl) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := secret.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.DecryptInit(s.handle, &mechanism, secret.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Object returns the underlying object of this key.
func (secret secretKeyImpl) Object() Object {
	return objectImpl(secret)
}

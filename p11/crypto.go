package p11

import "github.com/miekg/pkcs11"

// PublicKey is an Object representing a public key. Since the PublicKey method
// can be called on any object, it is the user's responsibility to ensure that
// the object is actually a public key. For instance, if you use a FindObjects
// template that includes CKA_CLASS: CKO_PUBLIC_KEY, you can be confident the
// resulting object is a public key.
type PublicKey interface {
	Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error)
	Verify(mechanism pkcs11.Mechanism, message, signature []byte) error
}

// PrivateKey is an Object representing a private key. Since the PrivateKey
// method can be called on any object, it is the user's responsibility to
// ensure that the object is actually a private key.
type PrivateKey interface {
	Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error)
	Sign(mechanism pkcs11.Mechanism, message []byte) ([]byte, error)
	Derive(mechanism pkcs11.Mechanism, attributes []*pkcs11.Attribute) ([]byte, error)
}

// PublicKey is an Object representing a public key. Since the PublicKey method
// can be called on any object, it is the user's responsibility to ensure that
// the object is actually a public key. For instance, if you use a FindObjects
// template that includes CKA_CLASS: CKO_PUBLIC_KEY, you can be confident the
// resulting object is a public key.
type publicKeyImpl objectImpl

// PrivateKey is an Object representing a private key. Since the PrivateKey
// method can be called on any object, it is the user's responsibility to
// ensure that the object is actually a private key.
type privateKeyImpl objectImpl

// Decrypt decrypts the input with a given mechanism.
func (priv privateKeyImpl) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.DecryptInit(s.handle, &mechanism, priv.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Sign signs the input with a given mechanism.
func (priv privateKeyImpl) Sign(mechanism pkcs11.Mechanism, message []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.SignInit(s.handle, &mechanism, priv.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Sign(s.handle, message)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (priv privateKeyImpl) deriveInner(mechanism pkcs11.Mechanism, attributes []*pkcs11.Attribute) (Object, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	objectHandle, err := s.ctx.DeriveKey(s.handle, &mechanism, priv.objectHandle, attributes)
	if err != nil {
		return nil, err
	}

	obj := objectImpl{
		session:      s,
		objectHandle: objectHandle,
	}
	return &obj, nil
}

// Derive derives a shared secret with a given mechanism.
func (priv privateKeyImpl) Derive(mechanism pkcs11.Mechanism, attributes []*pkcs11.Attribute) ([]byte, error) {
	sharedObj, err := priv.deriveInner(mechanism, attributes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := sharedObj.Value()
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// Verify verifies a signature over a message with a given mechanism.
func (pub publicKeyImpl) Verify(mechanism pkcs11.Mechanism, message, signature []byte) error {
	s := pub.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.VerifyInit(s.handle, &mechanism, pub.objectHandle)
	if err != nil {
		return err
	}
	err = s.ctx.Verify(s.handle, message, signature)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt encrypts a plaintext with a given mechanism.
func (pub publicKeyImpl) Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	s := pub.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.EncryptInit(s.handle, &mechanism, pub.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

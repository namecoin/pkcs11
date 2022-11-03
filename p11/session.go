package p11

import (
	"errors"
	"sync"

	"github.com/miekg/pkcs11"
)

// ErrNoObjectsFound is returned by FindObject() and FindObjects() if no objects are found.
var ErrNoObjectsFound = errors.New("no objects found")

// ErrTooManyObjectsFound is returned by FindObject() if multiple objects are found.
var ErrTooManyObjectsFound = errors.New("too many objects matching template")

// Session represents a PKCS#11 session.
type Session interface {
	// Login logs into the token as a regular user. Note: According to PKCS#11,
	// logged-in state is a property of an application, rather than a session, but
	// you can only log in via a session. Keep this in mind when using multiple
	// sessions on the same token. Logging in to a token in any session will log
	// in all sessions on that token, and logging out will do the same. This is
	// particularly relevant for private keys with CKA_ALWAYS_AUTHENTICATE set
	// (like Yubikeys in PIV mode). See
	// https://github.com/letsencrypt/pkcs11key/blob/master/key.go for an example
	// of managing login state with a mutex.
	Login(pin string) error
	// LoginSecurityOfficer logs into the token as the security officer.
	LoginSecurityOfficer(pin string) error
	// LoginAs logs into the token with the given user type.
	LoginAs(userType uint, pin string) error
	// Logout logs out all sessions from the token (see Login).
	Logout() error
	// Close closes the session.
	Close() error

	// CreateObject creates an object on the token with the given attributes.
	CreateObject(template []*pkcs11.Attribute) (Object, error)
	// FindObject finds a single object in the token that matches the attributes in
	// the template. It returns error if there is not exactly one result, or if
	// there was an error during the find calls.
	FindObject(template []*pkcs11.Attribute) (Object, error)
	// FindObjects finds any objects in the token matching the template.
	FindObjects(template []*pkcs11.Attribute) ([]Object, error)
	// GenerateKeyPair generates a public/private key pair. It takes
	// GenerateKeyPairRequest instead of individual arguments so that attributes for
	// public and private keys can't be accidentally switched around.
	GenerateKeyPair(request GenerateKeyPairRequest) (*KeyPair, error)
	// GenerateRandom returns random bytes generated by the token.
	GenerateRandom(length int) ([]byte, error)

	// InitPIN initialize's the normal user's PIN.
	InitPIN(pin string) error
	// SetPIN modifies the PIN of the logged-in user. "old" should contain the
	// current PIN, and "new" should contain the new PIN to be set.
	SetPIN(old, new string) error
}

type sessionImpl struct {
	sync.Mutex
	ctx    pkcs11.Ctx
	handle pkcs11.SessionHandle
}

func (s *sessionImpl) FindPrivateKey(label string) (PrivateKey, error) {
	obj, err := s.findObjectWithClassAndLabel(pkcs11.CKO_PRIVATE_KEY, label)
	if err != nil {
		return obj.PrivateKey(), err
	}
	return obj.PrivateKey(), nil
}

func (s *sessionImpl) FindPublicKey(label string) (PublicKey, error) {
	obj, err := s.findObjectWithClassAndLabel(pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		return obj.PublicKey(), err
	}
	return obj.PublicKey(), nil
}

func (s *sessionImpl) FindSecretKey(label string) (SecretKey, error) {
	obj, err := s.findObjectWithClassAndLabel(pkcs11.CKO_SECRET_KEY, label)
	if err != nil {
		return obj.SecretKey(), err
	}
	return obj.SecretKey(), nil
}

func (s *sessionImpl) findObjectWithClassAndLabel(class uint, label string) (Object, error) {
	return s.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
}

func (s *sessionImpl) FindObject(template []*pkcs11.Attribute) (Object, error) {
	objects, err := s.FindObjects(template)
	if err != nil {
		return objectImpl{}, err
	}
	if len(objects) > 1 {
		return objectImpl{}, ErrTooManyObjectsFound
	}
	return objects[0], nil
}

func (s *sessionImpl) FindObjects(template []*pkcs11.Attribute) ([]Object, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return nil, err
	}

	var results []Object
	for {
		objectHandles, err := s.ctx.FindObjects(s.handle, 100)
		if err != nil {
			_ = s.ctx.FindObjectsFinal(s.handle)
			return nil, err
		} else if len(objectHandles) == 0 {
			break
		}
		i := len(results)
		results = append(results, make([]Object, len(objectHandles))...)
		for j, objectHandle := range objectHandles {
			results[i+j] = objectImpl{
				session:      s,
				objectHandle: objectHandle,
			}
		}
	}
	if err := s.ctx.FindObjectsFinal(s.handle); err != nil {
		return nil, err
	} else if len(results) == 0 {
		return nil, ErrNoObjectsFound
	}
	return results, nil
}

func (s *sessionImpl) Close() error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.CloseSession(s.handle)
}

func (s *sessionImpl) Login(pin string) error {
	return s.LoginAs(pkcs11.CKU_USER, pin)
}

func (s *sessionImpl) LoginSecurityOfficer(pin string) error {
	return s.LoginAs(pkcs11.CKU_SO, pin)
}

func (s *sessionImpl) LoginAs(userType uint, pin string) error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.Login(s.handle, userType, pin)
}

func (s *sessionImpl) Logout() error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.Logout(s.handle)
}

func (s *sessionImpl) GenerateRandom(length int) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	return s.ctx.GenerateRandom(s.handle, length)
}

func (s *sessionImpl) CreateObject(template []*pkcs11.Attribute) (Object, error) {
	s.Lock()
	defer s.Unlock()
	oh, err := s.ctx.CreateObject(s.handle, template)
	if err != nil {
		return objectImpl{}, err
	}
	return objectImpl{
		session:      s,
		objectHandle: oh,
	}, nil
}

func (s *sessionImpl) InitPIN(pin string) error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.InitPIN(s.handle, pin)
}

func (s *sessionImpl) SetPIN(old, new string) error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.SetPIN(s.handle, old, new)
}

// KeyPair contains two Objects: one for a public key and one for a private key.
// It represents these as PublicKey and PrivateKey types so they can by used for
// appropriate cryptographic operations.
type KeyPair struct {
	Public  PublicKey
	Private PrivateKey
}

// GenerateKeyPairRequest contains the fields used to generate a key pair.
type GenerateKeyPairRequest struct {
	Mechanism            pkcs11.Mechanism
	PublicKeyAttributes  []*pkcs11.Attribute
	PrivateKeyAttributes []*pkcs11.Attribute
}

func (s *sessionImpl) GenerateKeyPair(request GenerateKeyPairRequest) (*KeyPair, error) {
	s.Lock()
	defer s.Unlock()
	pubHandle, privHandle, err := s.ctx.GenerateKeyPair(s.handle,
		&request.Mechanism,
		request.PublicKeyAttributes,
		request.PrivateKeyAttributes)
	if err != nil {
		return nil, err
	}

	pubObj := Object{
		session:      s,
		objectHandle: pubHandle,
	}
	privObj := Object{
		session:      s,
		objectHandle: privHandle,
	}
	return &KeyPair{
		Public: pubObj.PublicKey(),
		Private: privObj.PrivateKey(),
	}, nil
}

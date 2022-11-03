package p11

import (
	"errors"

	"github.com/miekg/pkcs11"
)

// ErrAttributeNotFound is returned by Attrbibute() if the searched attribute isn't found.
var ErrAttributeNotFound = errors.New("attribute not found")

// ErrTooManyAttributesFound is returned by Attrbibute() if the search returned multiple attributes.
var ErrTooManyAttributesFound = errors.New("too many attributes found")

// Object represents a handle to a PKCS#11 object. It is attached to the
// session used to find it. Once that session is closed, operations on the
// Object will fail. Operations may also depend on the logged-in state of
// the application.
type Object interface {
	Attribute(attributeType uint) ([]byte, error)
	Copy(template []*pkcs11.Attribute) (Object, error)
	Destroy() error
	Label() (string, error)
	Set(attributeType uint, value []byte) error
	Value() ([]byte, error)
}

// objectImpl represents a handle to a PKCS#11 object. It is attached to the
// session used to find it. Once that session is closed, operations on the
// Object will fail. Operations may also depend on the logged-in state of
// the application.
type objectImpl struct {
	session      *sessionImpl
	objectHandle pkcs11.ObjectHandle
}

// Label returns the label of an object.
func (o objectImpl) Label() (string, error) {
	labelBytes, err := o.Attribute(pkcs11.CKA_LABEL)
	if err != nil {
		return "", err
	}
	return string(labelBytes), nil
}

// Value returns an object's CKA_VALUE attribute, as bytes.
func (o objectImpl) Value() ([]byte, error) {
	return o.Attribute(pkcs11.CKA_VALUE)
}

// Attribute gets exactly one attribute from a PKCS#11 object, returning
// an error if the attribute is not found, or if multiple attributes are
// returned. On success, it will return the value of that attribute as a slice
// of bytes. For attributes not present (i.e. CKR_ATTRIBUTE_TYPE_INVALID),
// Attribute returns a nil slice and nil error.
func (o objectImpl) Attribute(attributeType uint) ([]byte, error) {
	o.session.Lock()
	defer o.session.Unlock()

	attrs, err := o.session.ctx.GetAttributeValue(o.session.handle, o.objectHandle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, nil)})
	// The PKCS#11 spec states that C_GetAttributeValue may return
	// CKR_ATTRIBUTE_TYPE_INVALID if an object simply does not posses a given
	// attribute. We don't consider that an error, we just consider that
	// equivalent to an empty value.
	if err == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, ErrAttributeNotFound
	}
	if len(attrs) > 1 {
		return nil, ErrTooManyAttributesFound
	}
	return attrs[0].Value, nil
}

// Set sets exactly one attribute on this object.
func (o objectImpl) Set(attributeType uint, value []byte) error {
	o.session.Lock()
	defer o.session.Unlock()

	err := o.session.ctx.SetAttributeValue(o.session.handle, o.objectHandle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, value)})
	if err != nil {
		return err
	}
	return nil
}

// Copy makes a copy of this object, with the attributes in template applied on
// top of it, if possible.
func (o objectImpl) Copy(template []*pkcs11.Attribute) (Object, error) {
	s := o.session
	s.Lock()
	defer s.Unlock()
	newHandle, err := s.ctx.CopyObject(s.handle, o.objectHandle, template)
	if err != nil {
		return objectImpl{}, err
	}
	return objectImpl{
		session:      s,
		objectHandle: newHandle,
	}, nil
}

// Destroy destroys this object.
func (o objectImpl) Destroy() error {
	s := o.session
	s.Lock()
	defer s.Unlock()
	return s.ctx.DestroyObject(s.handle, o.objectHandle)
}

// PrivateKey returns this object as a PrivateKey.
func (o Object) PrivateKey() PrivateKey {
	return PrivateKey(o)
}

// PublicKey returns this object as a PublicKey.
func (o Object) PublicKey() PublicKey {
	return PublicKey(o)
}

// SecretKey returns this object as a SecretKey.
func (o Object) SecretKey() SecretKey {
	return SecretKey(o)
}

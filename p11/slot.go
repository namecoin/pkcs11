package p11

import "github.com/miekg/pkcs11"

// Slot represents a slot that may hold a token.
type Slot interface {
	CloseAllSessions() error
	ID() uint
	Info() (pkcs11.SlotInfo, error)
	InitToken(securityOfficerPIN string, tokenLabel string) error
	Mechanisms() ([]Mechanism, error)
	OpenSession() (Session, error)
	OpenSessionWithFlags(flags uint) (Session, error)
	OpenWriteSession() (Session, error)
	TokenInfo() (pkcs11.TokenInfo, error)
}

// slotImpl represents a slot that may hold a token.
type slotImpl struct {
	ctx pkcs11.Ctx
	id  uint
}

// Info returns information about the Slot.
func (s slotImpl) Info() (pkcs11.SlotInfo, error) {
	return s.ctx.GetSlotInfo(s.id)
}

// TokenInfo returns information about the token in a Slot, if applicable.
func (s slotImpl) TokenInfo() (pkcs11.TokenInfo, error) {
	return s.ctx.GetTokenInfo(s.id)
}

// OpenSession opens a read-only session with the token in this slot.
func (s slotImpl) OpenSession() (Session, error) {
	return s.OpenSessionWithFlags(0)
}

// OpenWriteSession opens a read-write session with the token in this slot.
func (s slotImpl) OpenWriteSession() (Session, error) {
	return s.OpenSessionWithFlags(pkcs11.CKF_RW_SESSION)
}

// OpenSessionWithFlags opens a serial session using the given flags with the
// token in this slot.
// CKF_SERIAL_SESSION is always mandatory (per PKCS#11) for legacy reasons and
// is internally added before opening a session.
func (s slotImpl) OpenSessionWithFlags(flags uint) (Session, error) {
	handle, err := s.ctx.OpenSession(s.id, flags|pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, err
	}
	return &sessionImpl{
		ctx:    s.ctx,
		handle: handle,
	}, nil
}

// CloseAllSessions closes all sessions on this slot.
func (s slotImpl) CloseAllSessions() error {
	return s.ctx.CloseAllSessions(s.id)
}

// Mechanisms returns a list of Mechanisms available on the token in this
// slot.
func (s slotImpl) Mechanisms() ([]Mechanism, error) {
	list, err := s.ctx.GetMechanismList(s.id)
	if err != nil {
		return nil, err
	}
	result := make([]Mechanism, len(list))
	for i, mech := range list {
		result[i] = Mechanism{
			mechanism: mech,
			slot:      s,
		}
	}
	return result, nil
}

// InitToken initializes the token in this slot, setting its label to
// tokenLabel. If the token was not previously initialized, its security officer
// PIN is set to the provided string. If the token is already initialized, the
// provided PIN will be checked against the existing security officer PIN, and
// the token will only be reinitialized if there is a match.
//
// According to PKCS#11: "When a token is initialized, all objects that can be
// destroyed are destroyed (i.e., all except for 'indestructible' objects such
// as keys built into the token). Also, access by the normal user is disabled
// until the SO sets the normal user’s PIN."
func (s slotImpl) InitToken(securityOfficerPIN string, tokenLabel string) error {
	return s.ctx.InitToken(s.id, securityOfficerPIN, tokenLabel)
}

// ID returns the slot's ID.
func (s slotImpl) ID() uint {
	return s.id
}

// Mechanism represents a cipher, signature algorithm, hash function, or other
// function that a token can perform.
type Mechanism interface {
	Type() uint
	Parameter() []byte
	Info() (pkcs11.MechanismInfo, error)
}

// mechanismImpl represents a cipher, signature algorithm, hash function, or other
// function that a token can perform.
type mechanismImpl struct {
	mechanism *pkcs11.Mechanism
	slot      slotImpl
}

// Type returns the type of mechanism.
func (m *mechanismImpl) Type() uint {
	return m.mechanism.Mechanism
}

// Parameter returns any parameters required by the mechanism.
func (m *mechanismImpl) Parameter() []byte {
	return m.mechanism.Parameter
}

// Info returns information about this mechanism.
func (m *mechanismImpl) Info() (pkcs11.MechanismInfo, error) {
	return m.slot.ctx.GetMechanismInfo(m.slot.id, m.mechanism)
}

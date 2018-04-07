package types

import (
	"errors"
	"fmt"
	"time"

	crypto "github.com/tendermint/go-crypto"
	"github.com/tendermint/tendermint/wire"
	cmn "github.com/tendermint/tmlibs/common"
)

var (
	ErrVoteUnexpectedStep            = errors.New("Unexpected step")
	ErrVoteInvalidValidatorIndex     = errors.New("Invalid validator index")
	ErrVoteOverweight                = errors.New("Overweight multiplicity")
	ErrVoteInvalidSignature          = errors.New("Invalid signature")
	ErrVoteInvalidBlockHash          = errors.New("Invalid block hash")
	ErrVoteNonDeterministicSignature = errors.New("Non-deterministic signature")
	ErrVoteNil                       = errors.New("Nil vote")
)

type ErrVoteConflictingVotes struct {
	dups []*DuplicateVoteEvidence
}

func (err *ErrVoteConflictingVotes) Error() string {
	addrs := make([]Address, len(err.dups))
	for i, d := range err.dups {
		addrs[i] = d.PubKeys[d.DuplicateIndex].Address()
	}
	return fmt.Sprintf("Conflicting votes from validators %v", addrs)
}

func NewConflictingVoteError(pubKeys []crypto.AggregatablePubKey, duplicateIndices []int, conflicts []*Vote, voteB *Vote) *ErrVoteConflictingVotes {
	dups := make([]*DuplicateVoteEvidence, len(conflicts))
	for i := 0; i < len(conflicts); i++ {
		dups[i] = &DuplicateVoteEvidence{
			PubKeys:        pubKeys,
			DuplicateIndex: duplicateIndices[i],
			VoteA:          conflicts[i],
			VoteB:          voteB,
		}
	}
	return &ErrVoteConflictingVotes{dups}
}

// Types of votes
// TODO Make a new type "VoteType"
const (
	VoteTypePrevote   = byte(0x01)
	VoteTypePrecommit = byte(0x02)
)

func IsVoteTypeValid(type_ byte) bool {
	switch type_ {
	case VoteTypePrevote:
		return true
	case VoteTypePrecommit:
		return true
	default:
		return false
	}
}

// Address is hex bytes. TODO: crypto.Address
type Address = cmn.HexBytes

// Represents a prevote, precommit, or commit vote from validators for consensus.
type Vote struct {
	ValidatorIndex []int64                      `json:"validator_index"`
	Height         int64                        `json:"height"`
	Round          int                          `json:"round"`
	Timestamp      time.Time                    `json:"timestamp"`
	Type           byte                         `json:"type"`
	BlockID        BlockID                      `json:"block_id"` // zero if vote is nil.
	Signature      crypto.AggregatableSignature `json:"signature"`
}

func (vote *Vote) SignBytes(chainID string) []byte {
	bz, err := wire.MarshalJSON(CanonicalJSONOnceVote{
		chainID,
		CanonicalVote(vote),
	})
	if err != nil {
		panic(err)
	}
	return bz
}

func (vote *Vote) Copy() *Vote {
	voteCopy := *vote
	return &voteCopy
}

func (vote *Vote) String() string {
	if vote == nil {
		return "nil-Vote"
	}
	var typeString string
	switch vote.Type {
	case VoteTypePrevote:
		typeString = "Prevote"
	case VoteTypePrecommit:
		typeString = "Precommit"
	default:
		cmn.PanicSanity("Unknown vote type")
	}

	return fmt.Sprintf("Vote{%v %v/%02d/%v(%v) %X %v}",
		vote.ValidatorIndex,
		vote.Height, vote.Round, vote.Type, typeString,
		cmn.Fingerprint(vote.BlockID.Hash), vote.Signature,
	)
}

func (vote *Vote) Verify(chainID string, pubKeys []crypto.AggregatablePubKey) error {
	if !pubKeys[0].VerifyMultiSignatureWithMultiplicity(vote.SignBytes(chainID), pubKeys, vote.ValidatorIndex, vote.Signature) {
		return ErrVoteInvalidSignature
	}
	return nil
}

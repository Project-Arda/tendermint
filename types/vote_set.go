package types

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/pkg/errors"

	cmn "github.com/tendermint/tmlibs/common"
)

// UNSTABLE
// XXX: duplicate of p2p.ID to avoid dependence between packages.
// Perhaps we can have a minimal types package containing this (and other things?)
// that both `types` and `p2p` import ?
type P2PID string

/*
	VoteSet helps collect signatures from validators at each height+round for a
	predefined vote type.

	We need VoteSet to be able to keep track of conflicting votes when validators
	double-sign.  Yet, we can't keep track of *all* the votes seen, as that could
	be a DoS attack vector.

	There are two storage areas for votes.
	1. voteSet.votes
	2. voteSet.votesByBlock

	`.votes` is the "canonical" list of votes.  It always has at least one vote,
	if a vote from a validator had been seen at all.  Usually it keeps track of
	the first vote seen, but when a 2/3 majority is found, votes for that get
	priority and are copied over from `.votesByBlock`.

	`.votesByBlock` keeps track of a list of votes for a particular block.  There
	are two ways a &blockVotes{} gets created in `.votesByBlock`.
	1. the first vote seen by a validator was for the particular block.
	2. a peer claims to have seen 2/3 majority for the particular block.

	Since the first vote from a validator will always get added in `.votesByBlock`
	, all votes in `.votes` will have a corresponding entry in `.votesByBlock`.

	When a &blockVotes{} in `.votesByBlock` reaches a 2/3 majority quorum, its
	votes are copied into `.votes`.

	All this is memory bounded because conflicting votes only get added if a peer
	told us to track that block, each peer only gets to tell us 1 such block, and,
	there's only a limited number of peers.

	NOTE: Assumes that the sum total of voting power does not exceed MaxUInt64.
*/
type VoteSet struct {
	chainID string
	height  int64
	round   int
	type_   byte

	mtx           sync.Mutex
	valSet        *ValidatorSet
	votesBitArray *cmn.BitArray
	votes         []*Vote                // Primary votes to share
	count         int                    // Number of votes filled in
	sum           int64                  // Sum of voting power for seen votes, discounting conflicts
	maj23         *BlockID               // First 2/3 majority seen
	votesByBlock  map[string]*blockVotes // string(blockHash|blockParts) -> blockVotes
	peerMaj23s    map[P2PID]BlockID      // Maj23 for each peer
}

// Constructs a new VoteSet struct used to accumulate votes for given height/round.
func NewVoteSet(chainID string, height int64, round int, type_ byte, valSet *ValidatorSet) *VoteSet {
	if height == 0 {
		cmn.PanicSanity("Cannot make VoteSet for height == 0, doesn't make sense.")
	}
	return &VoteSet{
		chainID:       chainID,
		height:        height,
		round:         round,
		type_:         type_,
		valSet:        valSet,
		votesBitArray: cmn.NewBitArray(valSet.Size()),
		votes:         make([]*Vote, valSet.Size()),
		sum:           0,
		maj23:         nil,
		votesByBlock:  make(map[string]*blockVotes, valSet.Size()),
		peerMaj23s:    make(map[P2PID]BlockID),
	}
}

func (voteSet *VoteSet) ChainID() string {
	return voteSet.chainID
}

func (voteSet *VoteSet) Height() int64 {
	if voteSet == nil {
		return 0
	} else {
		return voteSet.height
	}
}

func (voteSet *VoteSet) Round() int {
	if voteSet == nil {
		return -1
	} else {
		return voteSet.round
	}
}

func (voteSet *VoteSet) Type() byte {
	if voteSet == nil {
		return 0x00
	} else {
		return voteSet.type_
	}
}

func (voteSet *VoteSet) Size() int {
	if voteSet == nil {
		return 0
	} else {
		return voteSet.valSet.Size()
	}
}

// Returns added=true if vote is valid and new.
// Otherwise returns err=ErrVote[
//		UnexpectedStep | InvalidIndex | InvalidAddress |
//		InvalidSignature | InvalidBlockHash | ConflictingVotes ]
// Duplicate votes return added=false, err=nil.
// Conflicting votes return added=*, err=ErrVoteConflictingVotes.
// NOTE: vote should not be mutated after adding.
// NOTE: VoteSet must not be nil
// NOTE: Vote must not be nil
func (voteSet *VoteSet) AddVote(vote *Vote) (added bool, err error) {
	if voteSet == nil {
		cmn.PanicSanity("AddVote() on nil VoteSet")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	return voteSet.addVote(vote)
}

// NOTE: Validates as much as possible before attempting to verify the signature.
func (voteSet *VoteSet) addVote(vote *Vote) (added bool, err error) {
	if vote == nil {
		return false, ErrVoteNil
	}
	valIndex := vote.ValidatorIndex
	blockKey := vote.BlockID.Key()

	// Ensure that validator index was set
	if valIndex == nil {
		return false, errors.Wrap(ErrVoteInvalidValidatorIndex, "Index is nil")
	}
	//check that multipliity array has same length as validator array
	if len(valIndex) != voteSet.valSet.Size() {
		return false, errors.Wrap(ErrVoteInvalidValidatorIndex, "Index wrong length")
	}

	// Make sure the step matches.
	if (vote.Height != voteSet.height) ||
		(vote.Round != voteSet.round) ||
		(vote.Type != voteSet.type_) {
		return false, errors.Wrapf(ErrVoteUnexpectedStep, "Got %d/%d/%d, expected %d/%d/%d",
			voteSet.height, voteSet.round, voteSet.type_,
			vote.Height, vote.Round, vote.Type)
	}

	//Check that max multiplicity is justified by total
	//pull voting power for each validator, add together, check math
	//TODO separate function, readable code, comments explaining logic
	var maxWeight int64 = 0
	var voteValue int64 = 0
	numBits := uint8(16) //FIXME should be set by config, or possibly changed over time
	for i, m := range valIndex {
		if m > maxWeight {
			maxWeight = m
		}
		if m != 0 {
			_, val := voteSet.valSet.GetByIndex(i)
			voteValue += val.VotingPower
		}
	}
	maxAllowableWeight := (int64(1) << (numBits - uint8(math.Ceil(math.Log2(float64(voteSet.valSet.TotalVotingPower())/(3*float64(voteValue))))))) - 1
	if maxWeight > maxAllowableWeight {
		return false, errors.Wrap(ErrVoteInvalidValidatorIndex, "Voting power not high enough for multiplciity")
	}

	//check that vote has non-trivial union difference with voteSet.votesByBlock[blockKey]
	voteblock, ok := voteSet.votesByBlock[blockKey]
	if ok {
		fresh := false
		for i, m := range valIndex {
			if !voteblock.bitArray.GetIndex(i) && m != 0 {
				fresh = true
			}
		}
		if fresh == false {
			return false, nil //We already have votes from all these validators for this block
			//TODO may be useful as a reduction element though, should still attempt
		}
	}

	//Check signature
	if err := vote.Verify(voteSet.chainID, voteSet.valSet.GetPubKeys()); err != nil {
		return false, errors.Wrapf(err, "Failed to verify vote with ChainID %s and Multi %s", voteSet.chainID, fmt.Sprint(vote.ValidatorIndex))
	}

	// Add vote and get conflicting vote if any
	added, conflicting, idx := voteSet.addVerifiedVote(vote, blockKey)
	if len(conflicting) != 0 {
		return added, NewConflictingVoteError(voteSet.valSet.GetPubKeys(), idx, conflicting, vote)
	} else {
		if !added {
			cmn.PanicSanity("Expected to add non-conflicting vote")
		}
		return added, nil
	}

}

// Returns (vote, true) if vote exists for valIndex and blockKey
// func (voteSet *VoteSet) getVote(valIndex int, blockKey string) (vote *Vote, ok bool) {
// 	if existing := voteSet.votes[valIndex]; existing != nil && existing.BlockID.Key() == blockKey {
// 		return existing, true
// 	}
// 	if existing := voteSet.votesByBlock[blockKey].getByIndex(valIndex); existing != nil {
// 		return existing, true
// 	}
// 	return nil, false
// }

// Assumes signature is valid.
// If conflicting vote exists, returns it.
func (voteSet *VoteSet) addVerifiedVote(vote *Vote, blockKey string) (added bool, conflicting []*Vote, conflictingIdx []int) {
	valIndex := vote.ValidatorIndex
	conflicting = make([]*Vote, 0)
	conflictingIdx = make([]int, 0)

	for key, bvotes := range voteSet.votesByBlock {
		if key != blockKey {
			for i, m := range valIndex {
				if bvotes.bitArray.GetIndex(i) && m != 0 {
					conflicting = append(conflicting, bvotes.getByIndex(i))
					conflictingIdx = append(conflictingIdx, i)
				}
			}
		}
	}

	if len(conflicting) == 0 || (voteSet.maj23 != nil && voteSet.maj23.Key() == blockKey) {
		voteSet.votes[voteSet.count] = vote
		voteSet.count += 1
		//TODO reduce current voteSet
		for i, m := range valIndex {
			if m != 0 {
				voteSet.votesBitArray.SetIndex(i, true)
			}
		}
		voteSet.sum = voteSet.valSet.GetSubsetVotingPower(voteSet.votesBitArray)
	}

	votesByBlock, ok := voteSet.votesByBlock[blockKey]
	if ok {
		if len(conflicting) != 0 && !votesByBlock.peerMaj23 {
			return false, conflicting, conflictingIdx //FIXME is this consistent?
		}
	} else {
		if len(conflicting) != 0 {
			return false, conflicting, conflictingIdx //FIXME check this too
		}
		votesByBlock = newBlockVotes(false, voteSet.valSet.Size())
		voteSet.votesByBlock[blockKey] = votesByBlock
	}

	// Before adding to votesByBlock, see if we'll exceed quorum
	origSum := votesByBlock.sum
	quorum := voteSet.valSet.TotalVotingPower()*2/3 + 1

	// Add vote to votesByBlock
	votesByBlock.addVerifiedVote(vote, voteSet.valSet)

	// If we just crossed the quorum threshold and have 2/3 majority...
	if origSum < quorum && quorum <= votesByBlock.sum {
		// Only consider the first quorum reached
		if voteSet.maj23 == nil {
			maj23BlockID := vote.BlockID
			voteSet.maj23 = &maj23BlockID
			// And also copy votes over to voteSet.votes
			//FIXME, do equiv thing
			// for i, vote := range votesByBlock.votes {
			// 	if vote != nil {
			// 		voteSet.votes[i] = vote
			// 	}
			// }
		}
	}

	return true, conflicting, conflictingIdx
}

// If a peer claims that it has 2/3 majority for given blockKey, call this.
// NOTE: if there are too many peers, or too much peer churn,
// this can cause memory issues.
// TODO: implement ability to remove peers too
// NOTE: VoteSet must not be nil
func (voteSet *VoteSet) SetPeerMaj23(peerID P2PID, blockID BlockID) error {
	if voteSet == nil {
		cmn.PanicSanity("SetPeerMaj23() on nil VoteSet")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	blockKey := blockID.Key()

	// Make sure peer hasn't already told us something.
	if existing, ok := voteSet.peerMaj23s[peerID]; ok {
		if existing.Equals(blockID) {
			return nil // Nothing to do
		} else {
			return fmt.Errorf("SetPeerMaj23: Received conflicting blockID from peer %v. Got %v, expected %v",
				peerID, blockID, existing)
		}
	}
	voteSet.peerMaj23s[peerID] = blockID

	// Create .votesByBlock entry if needed.
	votesByBlock, ok := voteSet.votesByBlock[blockKey]
	if ok {
		if votesByBlock.peerMaj23 {
			return nil // Nothing to do
		} else {
			votesByBlock.peerMaj23 = true
			// No need to copy votes, already there.
		}
	} else {
		votesByBlock = newBlockVotes(true, voteSet.valSet.Size())
		voteSet.votesByBlock[blockKey] = votesByBlock
		// No need to copy votes, no votes to copy over.
	}
	return nil
}

func (voteSet *VoteSet) BitArray() *cmn.BitArray {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.votesBitArray.Copy()
}

func (voteSet *VoteSet) BitArrayByBlockID(blockID BlockID) *cmn.BitArray {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	votesByBlock, ok := voteSet.votesByBlock[blockID.Key()]
	if ok {
		return votesByBlock.bitArray.Copy()
	}
	return nil
}

// // NOTE: if validator has conflicting votes, returns "canonical" vote
// func (voteSet *VoteSet) GetByIndex(valIndex int) *Vote {
// 	if voteSet == nil {
// 		return nil
// 	}
// 	voteSet.mtx.Lock()
// 	defer voteSet.mtx.Unlock()
// 	return voteSet.votes[valIndex]
// }

func (voteSet *VoteSet) HasTwoThirdsMajority() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

func (voteSet *VoteSet) IsCommit() bool {
	if voteSet == nil {
		return false
	}
	if voteSet.type_ != VoteTypePrecommit {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

func (voteSet *VoteSet) HasTwoThirdsAny() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.sum > voteSet.valSet.TotalVotingPower()*2/3
}

func (voteSet *VoteSet) HasAll() bool {
	return voteSet.sum == voteSet.valSet.TotalVotingPower()
}

// Returns either a blockhash (or nil) that received +2/3 majority.
// If there exists no such majority, returns (nil, PartSetHeader{}, false).
func (voteSet *VoteSet) TwoThirdsMajority() (blockID BlockID, ok bool) {
	if voteSet == nil {
		return BlockID{}, false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	if voteSet.maj23 != nil {
		return *voteSet.maj23, true
	} else {
		return BlockID{}, false
	}
}

func (voteSet *VoteSet) String() string {
	if voteSet == nil {
		return "nil-VoteSet"
	}
	return voteSet.StringIndented("")
}

func (voteSet *VoteSet) StringIndented(indent string) string {
	voteStrings := make([]string, len(voteSet.votes))
	for i, vote := range voteSet.votes {
		if vote == nil {
			voteStrings[i] = "nil-Vote"
		} else {
			voteStrings[i] = vote.String()
		}
	}
	return fmt.Sprintf(`VoteSet{
%s  H:%v R:%v T:%v
%s  %v
%s  %v
%s  %v
%s}`,
		indent, voteSet.height, voteSet.round, voteSet.type_,
		indent, strings.Join(voteStrings, "\n"+indent+"  "),
		indent, voteSet.votesBitArray,
		indent, voteSet.peerMaj23s,
		indent)
}

func (voteSet *VoteSet) StringShort() string {
	if voteSet == nil {
		return "nil-VoteSet"
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return fmt.Sprintf(`VoteSet{H:%v R:%v T:%v +2/3:%v %v %v}`,
		voteSet.height, voteSet.round, voteSet.type_, voteSet.maj23, voteSet.votesBitArray, voteSet.peerMaj23s)
}

//--------------------------------------------------------------------------------
// Commit

func (voteSet *VoteSet) MakeCommit() *Commit {
	if voteSet.type_ != VoteTypePrecommit {
		cmn.PanicSanity("Cannot MakeCommit() unless VoteSet.Type is VoteTypePrecommit")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	// Make sure we have a 2/3 majority
	if voteSet.maj23 == nil {
		cmn.PanicSanity("Cannot MakeCommit() unless a blockhash has +2/3")
	}

	// For every validator, get the precommit
	votesCopy := make([]*Vote, len(voteSet.votes))
	copy(votesCopy, voteSet.votes)
	empty := cmn.NewBitArray(voteSet.valSet.Size())
	cmt := voteSet.votesByBlock[voteSet.maj23.Key()].GetBestVoteFor(voteSet.valSet, empty)
	return &Commit{
		BlockID:    *voteSet.maj23,
		Precommits: cmt,
	}
}

//--------------------------------------------------------------------------------

/*
	Votes for a particular block
	There are two ways a *blockVotes gets created for a blockKey.
	1. first (non-conflicting) vote of a validator w/ blockKey (peerMaj23=false)
	2. A peer claims to have a 2/3 majority w/ blockKey (peerMaj23=true)
*/
type blockVotes struct {
	peerMaj23 bool          // peer claims to have maj23
	bitArray  *cmn.BitArray // valIndex -> hasVote?
	votes     []*Vote       // valIndex -> *Vote
	count     int           // number of separate votes stored
	sum       int64         // vote sum
}

func newBlockVotes(peerMaj23 bool, numValidators int) *blockVotes {
	return &blockVotes{
		peerMaj23: peerMaj23,
		bitArray:  cmn.NewBitArray(numValidators),
		votes:     make([]*Vote, numValidators),
		count:     0,
		sum:       0,
	}
}

func (vs *blockVotes) addVerifiedVote(vote *Vote, valSet *ValidatorSet) {
	for i, m := range vote.ValidatorIndex {
		if m != 0 {
			vs.bitArray.SetIndex(i, true)
		}
	}
	vs.votes[vs.count] = vote
	vs.count += 1
	//TODO reduce current voteSet with LLL
	vs.sum = valSet.GetSubsetVotingPower(vs.bitArray)
}

func (vs *blockVotes) GetBestVoteFor(valSet *ValidatorSet, current *cmn.BitArray) (vote *Vote) {
	//FIXME
	/*
		Needs to flip bits of current to get target
		then find best linear combination of known vote vectors whose sum is closest to target
		also needs to check that weight is under limit for stake value

		used to construct final commit
	*/
	return vs.votes[0] //FIXME
}

func (vs *blockVotes) getByIndex(index int) *Vote {
	if vs == nil {
		return nil
	}
	//TODO, could cache this with an actual index
	//returns the first vote which has this validator
	for _, v := range vs.votes {
		if v.ValidatorIndex[index] != 0 {
			return v
		}
	}
	return nil
}

//--------------------------------------------------------------------------------

// Common interface between *consensus.VoteSet and types.Commit
type VoteSetReader interface {
	Height() int64
	Round() int
	Type() byte
	Size() int
	BitArray() *cmn.BitArray
	GetByIndex(int) *Vote
	IsCommit() bool
}

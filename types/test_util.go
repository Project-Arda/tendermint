package types

import "time"

func MakeCommit(blockID BlockID, height int64, round int,
	voteSet *VoteSet,
	validators []*PrivValidatorFS) (*Commit, error) {

	// all sign
	for i := 0; i < len(validators); i++ {
		var idx = make([]int64, len(validators))
		idx[i] = 1
		vote := &Vote{
			ValidatorIndex: idx,
			Height:         height,
			Round:          round,
			Timestamp:      time.Now().UTC(),
			Type:           VoteTypePrecommit,
			BlockID:        blockID,
		}

		_, err := signAddVote(validators[i], vote, voteSet)
		if err != nil {
			return nil, err
		}
	}

	return voteSet.MakeCommit(), nil
}

func signAddVote(privVal *PrivValidatorFS, vote *Vote, voteSet *VoteSet) (signed bool, err error) {
	vote.Signature, err = privVal.Signer.Sign(vote.SignBytes(voteSet.ChainID()))
	if err != nil {
		return false, err
	}
	return voteSet.AddVote(vote)
}

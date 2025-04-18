package main

import (
	"fmt"

	"github.com/protolambda/zrnt/eth2/beacon/altair"
	"github.com/protolambda/zrnt/eth2/beacon/bellatrix"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/zrnt/eth2/beacon/electra"
	"github.com/protolambda/zrnt/eth2/beacon/phase0"
	"github.com/protolambda/ztyp/tree"
)

func setupState(spec *common.Spec, state common.BeaconState, eth1Time common.Timestamp,
	eth1BlockHash common.Root, validators []phase0.KickstartValidatorData, effectiveBalance common.Gwei) error {

	if err := state.SetGenesisTime(eth1Time + spec.GENESIS_DELAY); err != nil {
		return err
	}
	var forkVersion common.Version
	var previousForkVersion common.Version
	switch state.(type) {
	case *electra.BeaconStateView:
		forkVersion = spec.ELECTRA_FORK_VERSION
		previousForkVersion = spec.DENEB_FORK_VERSION
	case *deneb.BeaconStateView:
		forkVersion = spec.DENEB_FORK_VERSION
		previousForkVersion = spec.CAPELLA_FORK_VERSION
	case *capella.BeaconStateView:
		forkVersion = spec.CAPELLA_FORK_VERSION
		previousForkVersion = spec.BELLATRIX_FORK_VERSION
	case *bellatrix.BeaconStateView:
		forkVersion = spec.BELLATRIX_FORK_VERSION
		previousForkVersion = spec.ALTAIR_FORK_VERSION
	case *altair.BeaconStateView:
		forkVersion = spec.ALTAIR_FORK_VERSION
		previousForkVersion = spec.GENESIS_FORK_VERSION
	default:
		forkVersion = spec.GENESIS_FORK_VERSION
		previousForkVersion = spec.GENESIS_FORK_VERSION
	}
	if err := state.SetFork(common.Fork{
		PreviousVersion: previousForkVersion,
		CurrentVersion:  forkVersion,
		Epoch:           common.GENESIS_EPOCH,
	}); err != nil {
		return err
	}
	// Empty deposit-tree
	eth1Dat := common.Eth1Data{
		DepositRoot:  phase0.NewDepositRootsView().HashTreeRoot(tree.GetHashFn()),
		DepositCount: 0,
		BlockHash:    eth1BlockHash,
	}
	if err := state.SetEth1Data(eth1Dat); err != nil {
		return err
	}
	// Leave the deposit index to 0. No deposits happened.
	if i, err := state.Eth1DepositIndex(); err != nil {
		return err
	} else if i != 0 {
		return fmt.Errorf("expected 0 deposit index in state, got %d", i)
	}
	var emptyBody tree.HTR
	switch state.(type) {
	case *electra.BeaconStateView:
		emptyBody = electra.BeaconBlockBodyType(spec).New()
	case *deneb.BeaconStateView:
		emptyBody = deneb.BeaconBlockBodyType(spec).New()
	case *capella.BeaconStateView:
		emptyBody = capella.BeaconBlockBodyType(spec).New()
	case *bellatrix.BeaconStateView:
		emptyBody = bellatrix.BeaconBlockBodyType(spec).New()
	case *altair.BeaconStateView:
		emptyBody = altair.BeaconBlockBodyType(spec).New()
	default:
		emptyBody = phase0.BeaconBlockBodyType(spec).New()
	}
	// Setting to a valid BeaconBlockBody HTR has become official test setup behavior in Deneb,
	// see initialize_beacon_state_from_eth1.
	latestHeader := &common.BeaconBlockHeader{
		BodyRoot: emptyBody.HashTreeRoot(tree.GetHashFn()),
	}
	if err := state.SetLatestBlockHeader(latestHeader); err != nil {
		return err
	}
	// Seed RANDAO with Eth1 entropy
	err := state.SeedRandao(spec, eth1BlockHash)
	if err != nil {
		return err
	}

	for _, v := range validators {
		v.Balance = effectiveBalance
		if err := state.AddValidator(spec, v.Pubkey, v.WithdrawalCredentials, v.Balance); err != nil {
			return err
		}
	}
	vals, err := state.Validators()
	if err != nil {
		return err
	}
	// Process activations
	for i := 0; i < len(validators); i++ {
		val, err := vals.Validator(common.ValidatorIndex(i))
		if err != nil {
			return err
		}
		if uint64(effectiveBalance) > 0 {
			val.SetEffectiveBalance(effectiveBalance)
		}
		vEff, err := val.EffectiveBalance()
		if err != nil {
			return err
		}

		maxEffectiveBalance := spec.MAX_EFFECTIVE_BALANCE
		if uint64(effectiveBalance) > 0 {
			maxEffectiveBalance = effectiveBalance
		}
		if vEff == maxEffectiveBalance {
			if err := val.SetActivationEligibilityEpoch(common.GENESIS_EPOCH); err != nil {
				return err
			}
			if err := val.SetActivationEpoch(common.GENESIS_EPOCH); err != nil {
				return err
			}
		}
	}
	if err := state.SetGenesisValidatorsRoot(vals.HashTreeRoot(tree.GetHashFn())); err != nil {
		return err
	}
	if st, ok := state.(common.SyncCommitteeBeaconState); ok {
		indicesBounded, err := common.LoadBoundedIndices(vals)
		if err != nil {
			return err
		}
		active := common.ActiveIndices(indicesBounded, common.GENESIS_EPOCH)
		indices, err := ComputeSyncCommitteeIndices(spec, state, common.GENESIS_EPOCH, active, effectiveBalance)
		if err != nil {
			return fmt.Errorf("failed to compute sync committee indices: %v", err)
		}
		pubs, err := common.NewPubkeyCache(vals)
		if err != nil {
			return err
		}
		// Note: A duplicate committee is assigned for the current and next committee at genesis
		syncCommittee, err := IndicesToSyncCommittee(indices, pubs)
		if err != nil {
			return err
		}
		syncCommitteeView, err := syncCommittee.View(spec)
		if err != nil {
			return err
		}
		if err := st.SetCurrentSyncCommittee((*common.SyncCommitteeView)(syncCommitteeView)); err != nil {
			return err
		}
		if err := st.SetNextSyncCommittee((*common.SyncCommitteeView)(syncCommitteeView)); err != nil {
			return err
		}
	}
	return nil
}

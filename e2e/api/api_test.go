package api_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/status-im/status-go/e2e"
	"github.com/status-im/status-go/geth/account"
	"github.com/status-im/status-go/geth/api"
	"github.com/status-im/status-go/geth/common"
	"github.com/status-im/status-go/geth/log"
	"github.com/status-im/status-go/geth/params"
	"github.com/status-im/status-go/geth/signal"
	"github.com/status-im/status-go/geth/txqueue"
	. "github.com/status-im/status-go/testing"
	"github.com/stretchr/testify/suite"
)

const (
	testChatID = "testChat"
)

func TestAPI(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

type APITestSuite struct {
	suite.Suite
	api *api.StatusAPI
}

func (s *APITestSuite) SetupTest() {
	s.api = api.NewStatusAPI()
	s.NotNil(s.api)
}

func (s *APITestSuite) TestCHTUpdate() {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "cht-updates")
	s.NoError(err)
	defer os.RemoveAll(tmpDir) //nolint: errcheck

	configJSON := `{
		"NetworkId": ` + strconv.Itoa(params.RopstenNetworkID) + `,
		"DataDir": "` + tmpDir + `",
		"LogLevel": "INFO",
		"RPCEnabled": true
	}`

	_, err = params.LoadNodeConfig(configJSON)
	s.NoError(err)
	// TODO(tiabc): Test that CHT is really updated.
}

func (s *APITestSuite) TestRaceConditions() {
	cnt := 25
	progress := make(chan struct{}, cnt)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	nodeConfig1, err := e2e.MakeTestNodeConfig(GetNetworkID())
	s.NoError(err)

	nodeConfig2, err := e2e.MakeTestNodeConfig(GetNetworkID())
	s.NoError(err)

	nodeConfigs := []*params.NodeConfig{nodeConfig1, nodeConfig2}

	var funcsToTest = []func(*params.NodeConfig){
		func(config *params.NodeConfig) {
			log.Info("StartNodeAsync()")
			_, err := s.api.StartNodeAsync(config)
			s.T().Logf("StartNodeAsync() for network: %d, error: %v", config.NetworkID, err)
			progress <- struct{}{}
		},
		func(config *params.NodeConfig) {
			log.Info("StopNodeAsync()")
			_, err := s.api.StopNodeAsync()
			s.T().Logf("StopNodeAsync(), error: %v", err)
			progress <- struct{}{}
		},
		func(config *params.NodeConfig) {
			log.Info("RestartNodeAsync()")
			_, err := s.api.RestartNodeAsync()
			s.T().Logf("RestartNodeAsync(), error: %v", err)
			progress <- struct{}{}
		},
		// TODO(adam): quarantined until it uses a different datadir
		// as otherwise it wipes out cached blockchain data.
		// func(config *params.NodeConfig) {
		// 	log.Info("ResetChainDataAsync()")
		// 	_, err := s.api.ResetChainDataAsync()
		// 	s.T().Logf("ResetChainDataAsync(), error: %v", err)
		// 	progress <- struct{}{}
		// },
	}

	// increase StartNode()/StopNode() population
	for i := 0; i < 5; i++ {
		funcsToTest = append(funcsToTest, funcsToTest[0], funcsToTest[1])
	}

	for i := 0; i < cnt; i++ {
		randConfig := nodeConfigs[rnd.Intn(len(nodeConfigs))]
		randFunc := funcsToTest[rnd.Intn(len(funcsToTest))]

		if rnd.Intn(100) > 75 { // introduce random delays
			time.Sleep(500 * time.Millisecond)
		}
		go randFunc(randConfig)
	}

	for range progress {
		cnt -= 1
		if cnt <= 0 {
			break
		}
	}

	time.Sleep(2 * time.Second) // so that we see some logs
	// just in case we have a node running
	s.api.StopNode() //nolint: errcheck
}

func (s *APITestSuite) TestCellsRemovedAfterSwitchAccount() {
	const itersCount = 5
	var (
		require   = s.Require()
		getChatId = func(id int) string {
			return testChatID + strconv.Itoa(id)
		}
	)

	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	address1, _, _, err := s.api.AccountManager().CreateAccount(TestConfig.Account1.Password)
	require.NoError(err)

	address2, _, _, err := s.api.AccountManager().CreateAccount(TestConfig.Account2.Password)
	require.NoError(err)

	err = s.api.SelectAccount(address1, TestConfig.Account1.Password)
	require.NoError(err)

	for i := 0; i < itersCount; i++ {
		_, e := s.api.JailManager().CreateCell(getChatId(i))
		require.NoError(e)
	}

	err = s.api.SelectAccount(address2, TestConfig.Account2.Password)
	require.NoError(err)

	for i := 0; i < itersCount; i++ {
		_, e := s.api.JailManager().Cell(getChatId(i))
		require.Error(e)
	}
}

// TestLogoutRemovesCells we want be sure that
// cells will be removed after the API call "Logout"
func (s *APITestSuite) TestLogoutRemovesCells() {
	var (
		err     error
		require = s.Require()
	)

	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	address1, _, _, err := s.api.AccountManager().CreateAccount(TestConfig.Account1.Password)
	require.NoError(err)

	err = s.api.SelectAccount(address1, TestConfig.Account1.Password)
	require.NoError(err)

	s.api.JailManager().CreateAndInitCell(testChatID)

	err = s.api.Logout()
	require.NoError(err)

	_, err = s.api.JailManager().Cell(testChatID)
	require.Error(err, "Expected that cells was removed")
}

func (s *APITestSuite) TestCreateChildAccount() bool {
	require := s.Require()

	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	// to make sure that we start with empty account (which might get populated during previous tests)
	require.NoError(s.api.Logout())

	keyStore, err := s.api.NodeManager().AccountKeyStore()
	require.NoError(err)

	// create an account
	createAccountResponse, err := s.api.CreateAccount(TestConfig.Account1.Password)
	require.Empty(err, "could not create account: %s", err)

	address, pubKey, mnemonic := createAccountResponse.Address, createAccountResponse.PubKey, createAccountResponse.Mnemonic
	s.T().Logf("Account created: {address: %s, key: %s, mnemonic:%s}", address, pubKey, mnemonic)

	acct, err := common.ParseAccountString(address)
	require.NoError(err, "can not get account from address: %v", err)

	// obtain decrypted key, and make sure that extended key (which will be used as root for sub-accounts) is present
	_, key, err := keyStore.AccountDecryptedKey(acct, TestConfig.Account1.Password)
	require.NoError(err, "can not obtain decrypted account key: %v", err)
	require.NotNil(key.ExtendedKey, "CKD#2 has not been generated for new account")

	// try creating sub-account, w/o selecting main account i.e. w/o login to main account
	_, err = s.api.CreateChildAccount("", TestConfig.Account1.Password)
	require.EqualValues(account.ErrNoAccountSelected, err, "expected error is not returned (tried to create sub-account w/o login): %v", err)

	err = s.api.SelectAccount(address, TestConfig.Account1.Password)
	require.NoError(err, "Test failed: could not select account: %v", err)

	// try to create sub-account with wrong password
	_, err = s.api.CreateChildAccount("", "wrong password")
	require.EqualError(err, "cannot retrieve a valid key for a given account: could not decrypt key with given passphrase", "expected error is not returned (tried to create sub-account with wrong password): %v", err)

	// create sub-account (from implicit parent)
	createSubAccountResponse1, err := s.api.CreateChildAccount("", TestConfig.Account1.Password)
	require.NoError(err, "Test failed: could not select account: %v", err)

	// make sure that sub-account index automatically progresses
	createSubAccountResponse2, err := s.api.CreateChildAccount("", TestConfig.Account1.Password)
	require.NoError(err, "cannot create sub-account: %v", err)
	require.NotEqual(createSubAccountResponse1.Address, createSubAccountResponse2.Address, "sub-account index auto-increament failed")
	require.NotEqual(createSubAccountResponse1.PubKey, createSubAccountResponse2.PubKey, "sub-account index auto-increament failed")

	// create sub-account (from explicit parent)
	createSubAccountResponse3, err := s.api.CreateChildAccount(createSubAccountResponse2.Address, TestConfig.Account1.Password)
	require.NoError(err, "cannot create sub-account: %v", err)

	subAccount1, subAccount2, subAccount3 := createSubAccountResponse1.Address, createSubAccountResponse2.Address, createSubAccountResponse3.Address
	subPubKey1, subPubKey2, subPubKey3 := createSubAccountResponse1.PubKey, createSubAccountResponse2.PubKey, createSubAccountResponse3.PubKey

	require.NotEqual(subAccount1, subAccount3, "sub-account index auto-increament failed: subAccount1 == subAccount3")
	require.NotEqual(subPubKey1, subPubKey3, "sub-account index auto-increament failed: subPubKey1 == subPubKey3")
	require.NotEqual(subAccount2, subAccount3, "sub-account index auto-increament failed: subAccount2 == subAccount3")
	require.NotEqual(subPubKey2, subPubKey3, "sub-account index auto-increament failed: subPubKey2 == subPubKey3")

	return true
}

func (s *APITestSuite) TestRecoverAccount() bool {
	require := s.Require()

	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	keyStore, _ := s.api.NodeManager().AccountKeyStore()

	// create an account
	accountInfo, err := s.api.CreateAccount(TestConfig.Account1.Password)
	require.NoError(err, "could not create account: %v", err)
	address := accountInfo.Address
	pubKey := accountInfo.PubKey
	mnemonic := accountInfo.Mnemonic
	s.T().Logf("Account created: {address: %s, key: %s, mnemonic:%s}", address, pubKey, mnemonic)

	// try recovering using password + mnemonic
	recoverAccountResponse, err := s.api.RecoverAccount(TestConfig.Account1.Password, mnemonic)
	require.NoError(err, "recover account failed: %v", err)

	addressCheck, pubKeyCheck := recoverAccountResponse.Address, recoverAccountResponse.PubKey
	require.Equal(address, addressCheck, "recover account details failed to pull the correct details for address")
	require.Equal(pubKey, pubKeyCheck, "recover account details failed to pull the correct details for pubKey")

	// now test recovering, but make sure that account/key file is removed i.e. simulate recovering on a new device
	account, err := common.ParseAccountString(address)
	require.NoError(err, "can not get account from address: %v", err)

	account, key, err := keyStore.AccountDecryptedKey(account, TestConfig.Account1.Password)
	require.NoError(err, "can not obtain decrypted account key: %v", err)
	extChild2String := key.ExtendedKey.String()

	err = keyStore.Delete(account, TestConfig.Account1.Password)
	require.NoError(err, "cannot remove accoun: %v", err)

	recoverAccountResponse, err = s.api.RecoverAccount(TestConfig.Account1.Password, mnemonic)
	require.NoError(err, "recover account failed (for non-cached account): %s", err)

	addressCheck, pubKeyCheck = recoverAccountResponse.Address, recoverAccountResponse.PubKey

	require.Equal(address, addressCheck, "recover account details failed to pull the correct details (for non-cached account) for address")
	require.Equal(pubKey, pubKeyCheck, "recover account details failed to pull the correct details (for non-cached account) for pubKey")

	// make sure that extended key exists and is imported ok too
	_, key, err = keyStore.AccountDecryptedKey(account, TestConfig.Account1.Password)
	require.NoError(err, "can not obtain decrypted account key: %v", err)
	require.Equal(extChild2String, key.ExtendedKey.String(), "CKD#2 key mismatch, expected: %s, got: %s", extChild2String, key.ExtendedKey.String())

	// make sure that calling import several times, just returns from cache (no error is expected)
	recoverAccountResponse, err = s.api.RecoverAccount(TestConfig.Account1.Password, mnemonic)
	require.NoError(err, "recover account failed (for non-cached account): %v", err)

	addressCheck, pubKeyCheck = recoverAccountResponse.Address, recoverAccountResponse.PubKey
	require.Equal(address, addressCheck, "recover account details failed to pull the correct details (for non-cached account) for address")
	require.Equal(pubKey, pubKeyCheck, "recover account details failed to pull the correct details (for non-cached account) for pubKey")

	// time to login with recovered data
	whisperService, err := s.api.NodeManager().WhisperService()
	require.NoError(err, "whisper service not running: %v", err)

	hasKeyPair := whisperService.HasKeyPair(pubKeyCheck)
	require.False(hasKeyPair, "identity already present in whisper")

	err = s.api.SelectAccount(addressCheck, TestConfig.Account1.Password)
	require.NoError(err, "Test failed: could not select account: %v", err)

	hasKeyPair = whisperService.HasKeyPair(pubKeyCheck)
	require.True(hasKeyPair, "identity not injected into whisper: %v", err)

	return true
}

func (s *APITestSuite) TestCompleteTransaction() bool {
	require := s.Require()

	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	txQueueManager := s.api.TxQueueManager()
	txQueue := txQueueManager.TransactionQueue()

	txQueue.Reset()
	EnsureNodeSync(s.api.NodeManager())

	// log into account from which transactions will be sent
	err = s.api.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password)
	require.NoError(err, "cannot select account: %v. Error %q", TestConfig.Account1.Address, err)

	// make sure you panic if transaction complete doesn't return
	queuedTxCompleted := make(chan struct{}, 1)
	abortPanic := make(chan struct{}, 1)
	common.PanicAfter(10*time.Second, abortPanic, "testCompleteTransaction")

	// replace transaction notification handler
	var txHash = ""
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var envelope signal.Envelope
		err := json.Unmarshal([]byte(jsonEvent), &envelope)
		require.NoError(err, "cannot unmarshal event's JSON: %s. Error %q", jsonEvent, err)
		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			s.T().Logf("transaction queued (will be completed shortly): {id: %s}\n", event["id"].(string))

			completeTxResponse := common.CompleteTransactionResult{}
			completeTxResponse, err := s.api.CompleteTransaction(common.QueuedTxID(event["id"].(string)), TestConfig.Account1.Password)
			require.NoError(err, "cannot complete queued transaction[%v]: %v", event["id"], completeTxResponse.Error)

			txHash = completeTxResponse.Hash

			s.T().Logf("transaction complete: https://testnet.etherscan.io/tx/%s", txHash)
			abortPanic <- struct{}{} // so that timeout is aborted
			queuedTxCompleted <- struct{}{}
		}
	})

	// this call blocks, up until Complete Transaction is called
	txCheckHash, err := s.api.SendTransaction(context.TODO(), common.SendTxArgs{
		From:  common.FromAddress(TestConfig.Account1.Address),
		To:    common.ToAddress(TestConfig.Account2.Address),
		Value: (*hexutil.Big)(big.NewInt(1000000000000)),
	})
	require.NoError(err, "Failed to SendTransaction: %s", err)

	<-queuedTxCompleted // make sure that complete transaction handler completes its magic, before we proceed

	require.Equal(txCheckHash.Hex(), txHash, "Transaction hash returned from SendTransaction is invalid: expected %s, got %s",
		txCheckHash.Hex(), txHash)

	require.NotEqual(gethcommon.Hash{}, txCheckHash, "Test failed: transaction was never queued or completed")

	require.Equal(0, txQueue.Count(), "tx queue must be empty at this point")

	return true
}

func (s *APITestSuite) TestCompleteMultipleQueuedTransactions() bool { //nolint: gocyclo
	require := s.Require()
	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	txQueue := s.api.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	err = s.api.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password)
	require.NoError(err, "cannot select account: %v", TestConfig.Account1.Address)

	// make sure you panic if transaction complete doesn't return
	testTxCount := 3
	txIDs := make(chan common.QueuedTxID, testTxCount)
	allTestTxCompleted := make(chan struct{}, 1)

	// replace transaction notification handler
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var txID common.QueuedTxID
		var envelope signal.Envelope
		err := json.Unmarshal([]byte(jsonEvent), &envelope)
		require.NoError(err, "cannot unmarshal event's JSON: %s", jsonEvent)

		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = common.QueuedTxID(event["id"].(string))
			s.T().Logf("transaction queued (will be completed in a single call, once aggregated): {id: %s}\n", txID)
			txIDs <- txID
		}
	})

	//  this call blocks, and should return when DiscardQueuedTransaction() for a given tx id is called
	sendTx := func() {
		txHashCheck, err := s.api.SendTransaction(context.TODO(), common.SendTxArgs{
			From:  common.FromAddress(TestConfig.Account1.Address),
			To:    common.ToAddress(TestConfig.Account2.Address),
			Value: (*hexutil.Big)(big.NewInt(1000000000000)),
		})
		require.NoError(err, "unexpected error: %v", err)

		require.NotEqual(gethcommon.Hash{}, txHashCheck, "transaction returned empty has")

	}

	// wait for transactions, and complete them in a single call
	completeTxs := func(txIDs []common.QueuedTxID) {
		txIDs = append(txIDs, "invalid-tx-id")

		// complete
		resultsStruct, errs := s.api.CompleteTransactions(txIDs, TestConfig.Account1.Password)
		results := resultsStruct.Results

		require.Len(results, testTxCount+1)
		require.Equal(errs[common.QueuedTxID("invalid-tx-id")], txqueue.ErrQueuedTxIDNotFound)

		for txID, txResult := range results {
			if txID == common.QueuedTxID("invalid-tx-id") {
				continue
			}

			require.Equal(txResult.ID, txID, "tx id not set in result: expected id is %s", txID)
			require.Equal("", txResult.Error, "invalid error for %s", txID)

			require.NotEqual(gethcommon.Hash{}.Hex(), txResult.Hash, "invalid hash (expected non empty hash): %s", txID)

			s.T().Logf("transaction complete: https://testnet.etherscan.io/tx/%s", txResult.Hash)
		}

		time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
		for _, txID := range txIDs {
			require.False(txQueue.Has(txID), "txqueue should not have test tx at this point (it should be completed): %s", txID)
		}
	}
	go func() {
		ids := make([]common.QueuedTxID, testTxCount)
		for i := 0; i < testTxCount; i++ {
			ids[i] = <-txIDs
		}

		completeTxs(ids)
		close(allTestTxCompleted)
	}()

	// send multiple transactions
	for i := 0; i < testTxCount; i++ {
		go sendTx()
	}

	select {
	case <-allTestTxCompleted:
		// pass
	case <-time.After(20 * time.Second):

		s.Fail("test timed out")
		return false
	}

	if txQueue.Count() != 0 {
		s.Fail("tx queue must be empty at this point")
		return false
	}

	return true
}

func (s *APITestSuite) TestDiscardTransaction() bool { //nolint: gocyclo
	require := s.Require()
	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	txQueue := s.api.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	err = s.api.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password)
	require.NoError(err, "cannot select account: %v", TestConfig.Account1.Address)

	// make sure you panic if transaction complete doesn't return
	completeQueuedTransaction := make(chan struct{}, 1)
	common.PanicAfter(20*time.Second, completeQueuedTransaction, "testDiscardTransaction")

	// replace transaction notification handler
	var txID common.QueuedTxID
	txFailedEventCalled := false
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var envelope signal.Envelope
		err := json.Unmarshal([]byte(jsonEvent), &envelope)
		require.NoError(err, "cannot unmarshal event's JSON: %s", jsonEvent)

		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = common.QueuedTxID(event["id"].(string))
			s.T().Logf("transaction queued (will be discarded soon): {id: %s}\n", txID)

			require.True(txQueue.Has(common.QueuedTxID(txID)), "txqueue should still have test tx: %s", txID)

			// discard
			discardResponse, err := s.api.DiscardTransaction(txID)
			require.NoError(err, "cannot discard tx: %v", discardResponse.Error)

			// try completing discarded transaction
			_, err = s.api.CompleteTransaction(txID, TestConfig.Account1.Password)
			require.Equal(txqueue.ErrQueuedTxIDNotFound, err, "expects tx not found, but call to CompleteTransaction succeeded")

			time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
			require.False(txQueue.Has(txID), "txqueue should not have test tx at this point (it should be discarded): %s", txID)

			completeQueuedTransaction <- struct{}{} // so that timeout is aborted
		}

		if envelope.Type == txqueue.EventTransactionFailed {
			event := envelope.Event.(map[string]interface{})
			s.T().Logf("transaction return event received: {id: %s}\n", event["id"].(string))

			receivedErrMessage := event["error_message"].(string)
			expectedErrMessage := txqueue.ErrQueuedTxDiscarded.Error()
			require.Equal(expectedErrMessage, receivedErrMessage, "unexpected error message received: got %v", receivedErrMessage)

			receivedErrCode := event["error_code"].(string)
			require.Equal(txqueue.SendTransactionDiscardedErrorCode, receivedErrCode, "unexpected error code received: got %v", receivedErrCode)

			txFailedEventCalled = true
		}
	})

	// this call blocks, and should return when DiscardQueuedTransaction() is called
	txHashCheck, err := s.api.SendTransaction(context.TODO(), common.SendTxArgs{
		From:  common.FromAddress(TestConfig.Account1.Address),
		To:    common.ToAddress(TestConfig.Account2.Address),
		Value: (*hexutil.Big)(big.NewInt(1000000000000)),
	})
	require.Equal(txqueue.ErrQueuedTxDiscarded, err, "expected error not thrown: %v", err)

	require.Equal(gethcommon.Hash{}, txHashCheck, "transaction returned hash, while it shouldn't")

	require.Equal(0, txQueue.Count(), "tx queue must be empty at this point")

	require.True(txFailedEventCalled, "expected tx failure signal is not received")

	return true
}

func (s *APITestSuite) TestDiscardMultipleQueuedTransactions() bool { //nolint: gocyclo
	require := s.Require()
	config, err := e2e.MakeTestNodeConfig(GetNetworkID())
	require.NoError(err)
	err = s.api.StartNode(config)
	require.NoError(err)
	defer s.api.StopNode() //nolint: errcheck

	txQueue := s.api.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	err = s.api.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password)
	require.NoError(err, "cannot select account: %v", TestConfig.Account1.Address)

	// make sure you panic if transaction complete doesn't return
	testTxCount := 3
	txIDs := make(chan common.QueuedTxID, testTxCount)
	allTestTxDiscarded := make(chan struct{}, 1)

	// replace transaction notification handler
	txFailedEventCallCount := 0
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var txID common.QueuedTxID
		var envelope signal.Envelope
		err := json.Unmarshal([]byte(jsonEvent), &envelope)
		require.NoError(err, "cannot unmarshal event's JSON: %s", jsonEvent)

		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = common.QueuedTxID(event["id"].(string))
			s.T().Logf("transaction queued (will be discarded soon): {id: %s}\n", txID)

			require.True(txQueue.Has(txID), "txqueue should still have test tx: %s", txID)

			txIDs <- txID
		}

		if envelope.Type == txqueue.EventTransactionFailed {
			event := envelope.Event.(map[string]interface{})
			s.T().Logf("transaction return event received: {id: %s}\n", event["id"].(string))

			receivedErrMessage := event["error_message"].(string)
			expectedErrMessage := txqueue.ErrQueuedTxDiscarded.Error()
			require.Equal(expectedErrMessage, receivedErrMessage, "unexpected error message received: got %v", receivedErrMessage)

			receivedErrCode := event["error_code"].(string)
			require.Equal(txqueue.SendTransactionDiscardedErrorCode, receivedErrCode, "unexpected error code received: got %v", receivedErrCode)

			txFailedEventCallCount++
			if txFailedEventCallCount == testTxCount {
				allTestTxDiscarded <- struct{}{}
			}
		}
	})

	// this call blocks, and should return when DiscardQueuedTransaction() for a given tx id is called
	sendTx := func() {
		txHashCheck, err := s.api.SendTransaction(context.TODO(), common.SendTxArgs{
			From:  common.FromAddress(TestConfig.Account1.Address),
			To:    common.ToAddress(TestConfig.Account2.Address),
			Value: (*hexutil.Big)(big.NewInt(1000000000000)),
		})
		require.Equal(txqueue.ErrQueuedTxDiscarded, err, "expected error not thrown: %v", err)
		require.Equal(gethcommon.Hash{}, txHashCheck, "transaction returned hash, while it shouldn't")

	}

	// wait for transactions, and discard immediately
	discardTxs := func(txIDs []common.QueuedTxID) {
		txIDs = append(txIDs, "invalid-tx-id")

		// discard
		discardResultsStruct, errs := s.api.DiscardTransactions(txIDs)
		discardResults := discardResultsStruct.Results

		require.Equal(1, len(discardResults))
		require.Equal(txqueue.ErrQueuedTxIDNotFound, errs["invalid-tx-id"])

		// try completing discarded transaction
		completeResultsStruct, errs := s.api.CompleteTransactions(txIDs, TestConfig.Account1.Password)
		completeResults := completeResultsStruct.Results

		require.Equal(testTxCount+1, len(completeResults), "unexpected number of errors (call to CompleteTransaction should not succeed)")

		for txID, txResult := range completeResults {
			require.Equal(txResult.ID, txID, "tx id not set in result: expected id is %s", txID)

			require.Equal(txqueue.ErrQueuedTxIDNotFound, errs[txID], "invalid error for %s", txResult.Hash)

			require.Equal(gethcommon.Hash{}.Hex(), txResult.Hash, "invalid hash (expected zero): %s", txResult.Hash)

		}

		time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
		for _, txID := range txIDs {
			require.False(txQueue.Has(txID), "txqueue should not have test tx at this point (it should be discarded): %s", txID)
		}
	}
	go func() {
		ids := make([]common.QueuedTxID, testTxCount)
		for i := 0; i < testTxCount; i++ {
			ids[i] = <-txIDs
		}

		discardTxs(ids)
	}()

	// send multiple transactions
	for i := 0; i < testTxCount; i++ {
		go sendTx()
	}

	select {
	case <-allTestTxDiscarded:
		// pass
	case <-time.After(20 * time.Second):
		s.FailNow("test timed out")
		return false
	}

	if txQueue.Count() != 0 {
		s.FailNow("tx queue must be empty at this point")
		return false
	}

	return true
}

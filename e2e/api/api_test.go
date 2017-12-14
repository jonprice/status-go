package api_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

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

func testCompleteTransaction(t *testing.T) bool {
	txQueueManager := statusAPI.TxQueueManager()
	txQueue := txQueueManager.TransactionQueue()

	txQueue.Reset()
	EnsureNodeSync(statusAPI.NodeManager())

	// log into account from which transactions will be sent
	if err := statusAPI.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password); err != nil {
		t.Errorf("cannot select account: %v. Error %q", TestConfig.Account1.Address, err)
		return false
	}

	// make sure you panic if transaction complete doesn't return
	queuedTxCompleted := make(chan struct{}, 1)
	abortPanic := make(chan struct{}, 1)
	common.PanicAfter(10*time.Second, abortPanic, "testCompleteTransaction")

	// replace transaction notification handler
	var txHash = ""
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var envelope signal.Envelope
		if err := json.Unmarshal([]byte(jsonEvent), &envelope); err != nil {
			t.Errorf("cannot unmarshal event's JSON: %s. Error %q", jsonEvent, err)
			return
		}
		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			t.Logf("transaction queued (will be completed shortly): {id: %s}\n", event["id"].(string))

			completeTxResponse := common.CompleteTransactionResult{}
			rawResponse := CompleteTransaction(C.CString(event["id"].(string)), C.CString(TestConfig.Account1.Password))

			if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &completeTxResponse); err != nil {
				t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
			}

			if completeTxResponse.Error != "" {
				t.Errorf("cannot complete queued transaction[%v]: %v", event["id"], completeTxResponse.Error)
			}

			txHash = completeTxResponse.Hash

			t.Logf("transaction complete: https://testnet.etherscan.io/tx/%s", txHash)
			abortPanic <- struct{}{} // so that timeout is aborted
			queuedTxCompleted <- struct{}{}
		}
	})

	// this call blocks, up until Complete Transaction is called
	txCheckHash, err := statusAPI.SendTransaction(context.TODO(), common.SendTxArgs{
		From:  common.FromAddress(TestConfig.Account1.Address),
		To:    common.ToAddress(TestConfig.Account2.Address),
		Value: (*hexutil.Big)(big.NewInt(1000000000000)),
	})
	if err != nil {
		t.Errorf("Failed to SendTransaction: %s", err)
		return false
	}

	<-queuedTxCompleted // make sure that complete transaction handler completes its magic, before we proceed

	if txHash != txCheckHash.Hex() {
		t.Errorf("Transaction hash returned from SendTransaction is invalid: expected %s, got %s",
			txCheckHash.Hex(), txHash)
		return false
	}

	if reflect.DeepEqual(txCheckHash, gethcommon.Hash{}) {
		t.Error("Test failed: transaction was never queued or completed")
		return false
	}

	if txQueue.Count() != 0 {
		t.Error("tx queue must be empty at this point")
		return false
	}

	return true
}

func testCompleteMultipleQueuedTransactions(t *testing.T) bool { //nolint: gocyclo
	txQueue := statusAPI.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	if err := statusAPI.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password); err != nil {
		t.Errorf("cannot select account: %v", TestConfig.Account1.Address)
		return false
	}

	// make sure you panic if transaction complete doesn't return
	testTxCount := 3
	txIDs := make(chan string, testTxCount)
	allTestTxCompleted := make(chan struct{}, 1)

	// replace transaction notification handler
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var txID string
		var envelope signal.Envelope
		if err := json.Unmarshal([]byte(jsonEvent), &envelope); err != nil {
			t.Errorf("cannot unmarshal event's JSON: %s", jsonEvent)
			return
		}
		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = event["id"].(string)
			t.Logf("transaction queued (will be completed in a single call, once aggregated): {id: %s}\n", txID)

			txIDs <- txID
		}
	})

	//  this call blocks, and should return when DiscardQueuedTransaction() for a given tx id is called
	sendTx := func() {
		txHashCheck, err := statusAPI.SendTransaction(context.TODO(), common.SendTxArgs{
			From:  common.FromAddress(TestConfig.Account1.Address),
			To:    common.ToAddress(TestConfig.Account2.Address),
			Value: (*hexutil.Big)(big.NewInt(1000000000000)),
		})
		if err != nil {
			t.Errorf("unexpected error thrown: %v", err)
			return
		}

		if reflect.DeepEqual(txHashCheck, gethcommon.Hash{}) {
			t.Error("transaction returned empty hash")
			return
		}
	}

	// wait for transactions, and complete them in a single call
	completeTxs := func(txIDStrings string) {
		var parsedIDs []string
		if err := json.Unmarshal([]byte(txIDStrings), &parsedIDs); err != nil {
			t.Error(err)
			return
		}

		parsedIDs = append(parsedIDs, "invalid-tx-id")
		updatedTxIDStrings, _ := json.Marshal(parsedIDs)

		// complete
		resultsString := CompleteTransactions(C.CString(string(updatedTxIDStrings)), C.CString(TestConfig.Account1.Password))
		resultsStruct := common.CompleteTransactionsResult{}
		if err := json.Unmarshal([]byte(C.GoString(resultsString)), &resultsStruct); err != nil {
			t.Error(err)
			return
		}
		results := resultsStruct.Results

		if len(results) != (testTxCount+1) || results["invalid-tx-id"].Error != txqueue.ErrQueuedTxIDNotFound.Error() {
			t.Errorf("cannot complete txs: %v", results)
			return
		}
		for txID, txResult := range results {
			if txID != txResult.ID {
				t.Errorf("tx id not set in result: expected id is %s", txID)
				return
			}
			if txResult.Error != "" && txID != "invalid-tx-id" {
				t.Errorf("invalid error for %s", txID)
				return
			}
			if txResult.Hash == zeroHash && txID != "invalid-tx-id" {
				t.Errorf("invalid hash (expected non empty hash): %s", txID)
				return
			}

			if txResult.Hash != zeroHash {
				t.Logf("transaction complete: https://testnet.etherscan.io/tx/%s", txResult.Hash)
			}
		}

		time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
		for _, txID := range parsedIDs {
			if txQueue.Has(common.QueuedTxID(txID)) {
				t.Errorf("txqueue should not have test tx at this point (it should be completed): %s", txID)
				return
			}
		}
	}
	go func() {
		var txIDStrings []string
		for i := 0; i < testTxCount; i++ {
			txIDStrings = append(txIDStrings, <-txIDs)
		}

		txIDJSON, _ := json.Marshal(txIDStrings)
		completeTxs(string(txIDJSON))
		allTestTxCompleted <- struct{}{}
	}()

	// send multiple transactions
	for i := 0; i < testTxCount; i++ {
		go sendTx()
	}

	select {
	case <-allTestTxCompleted:
		// pass
	case <-time.After(20 * time.Second):
		t.Error("test timed out")
		return false
	}

	if txQueue.Count() != 0 {
		t.Error("tx queue must be empty at this point")
		return false
	}

	return true
}

func testDiscardTransaction(t *testing.T) bool { //nolint: gocyclo
	txQueue := statusAPI.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	if err := statusAPI.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password); err != nil {
		t.Errorf("cannot select account: %v", TestConfig.Account1.Address)
		return false
	}

	// make sure you panic if transaction complete doesn't return
	completeQueuedTransaction := make(chan struct{}, 1)
	common.PanicAfter(20*time.Second, completeQueuedTransaction, "testDiscardTransaction")

	// replace transaction notification handler
	var txID string
	txFailedEventCalled := false
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var envelope signal.Envelope
		if err := json.Unmarshal([]byte(jsonEvent), &envelope); err != nil {
			t.Errorf("cannot unmarshal event's JSON: %s", jsonEvent)
			return
		}
		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = event["id"].(string)
			t.Logf("transaction queued (will be discarded soon): {id: %s}\n", txID)

			if !txQueue.Has(common.QueuedTxID(txID)) {
				t.Errorf("txqueue should still have test tx: %s", txID)
				return
			}

			// discard
			discardResponse := common.DiscardTransactionResult{}
			rawResponse := DiscardTransaction(C.CString(txID))

			if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &discardResponse); err != nil {
				t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
			}

			if discardResponse.Error != "" {
				t.Errorf("cannot discard tx: %v", discardResponse.Error)
				return
			}

			// try completing discarded transaction
			_, err := statusAPI.CompleteTransaction(common.QueuedTxID(txID), TestConfig.Account1.Password)
			if err != txqueue.ErrQueuedTxIDNotFound {
				t.Error("expects tx not found, but call to CompleteTransaction succeeded")
				return
			}

			time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
			if txQueue.Has(common.QueuedTxID(txID)) {
				t.Errorf("txqueue should not have test tx at this point (it should be discarded): %s", txID)
				return
			}

			completeQueuedTransaction <- struct{}{} // so that timeout is aborted
		}

		if envelope.Type == txqueue.EventTransactionFailed {
			event := envelope.Event.(map[string]interface{})
			t.Logf("transaction return event received: {id: %s}\n", event["id"].(string))

			receivedErrMessage := event["error_message"].(string)
			expectedErrMessage := txqueue.ErrQueuedTxDiscarded.Error()
			if receivedErrMessage != expectedErrMessage {
				t.Errorf("unexpected error message received: got %v", receivedErrMessage)
				return
			}

			receivedErrCode := event["error_code"].(string)
			if receivedErrCode != txqueue.SendTransactionDiscardedErrorCode {
				t.Errorf("unexpected error code received: got %v", receivedErrCode)
				return
			}

			txFailedEventCalled = true
		}
	})

	// this call blocks, and should return when DiscardQueuedTransaction() is called
	txHashCheck, err := statusAPI.SendTransaction(context.TODO(), common.SendTxArgs{
		From:  common.FromAddress(TestConfig.Account1.Address),
		To:    common.ToAddress(TestConfig.Account2.Address),
		Value: (*hexutil.Big)(big.NewInt(1000000000000)),
	})
	if err != txqueue.ErrQueuedTxDiscarded {
		t.Errorf("expected error not thrown: %v", err)
		return false
	}

	if !reflect.DeepEqual(txHashCheck, gethcommon.Hash{}) {
		t.Error("transaction returned hash, while it shouldn't")
		return false
	}

	if txQueue.Count() != 0 {
		t.Error("tx queue must be empty at this point")
		return false
	}

	if !txFailedEventCalled {
		t.Error("expected tx failure signal is not received")
		return false
	}

	return true
}

func testDiscardMultipleQueuedTransactions(t *testing.T) bool { //nolint: gocyclo
	txQueue := statusAPI.TxQueueManager().TransactionQueue()
	txQueue.Reset()

	// log into account from which transactions will be sent
	if err := statusAPI.SelectAccount(TestConfig.Account1.Address, TestConfig.Account1.Password); err != nil {
		t.Errorf("cannot select account: %v", TestConfig.Account1.Address)
		return false
	}

	// make sure you panic if transaction complete doesn't return
	testTxCount := 3
	txIDs := make(chan string, testTxCount)
	allTestTxDiscarded := make(chan struct{}, 1)

	// replace transaction notification handler
	txFailedEventCallCount := 0
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		var txID string
		var envelope signal.Envelope
		if err := json.Unmarshal([]byte(jsonEvent), &envelope); err != nil {
			t.Errorf("cannot unmarshal event's JSON: %s", jsonEvent)
			return
		}
		if envelope.Type == txqueue.EventTransactionQueued {
			event := envelope.Event.(map[string]interface{})
			txID = event["id"].(string)
			t.Logf("transaction queued (will be discarded soon): {id: %s}\n", txID)

			if !txQueue.Has(common.QueuedTxID(txID)) {
				t.Errorf("txqueue should still have test tx: %s", txID)
				return
			}

			txIDs <- txID
		}

		if envelope.Type == txqueue.EventTransactionFailed {
			event := envelope.Event.(map[string]interface{})
			t.Logf("transaction return event received: {id: %s}\n", event["id"].(string))

			receivedErrMessage := event["error_message"].(string)
			expectedErrMessage := txqueue.ErrQueuedTxDiscarded.Error()
			if receivedErrMessage != expectedErrMessage {
				t.Errorf("unexpected error message received: got %v", receivedErrMessage)
				return
			}

			receivedErrCode := event["error_code"].(string)
			if receivedErrCode != txqueue.SendTransactionDiscardedErrorCode {
				t.Errorf("unexpected error code received: got %v", receivedErrCode)
				return
			}

			txFailedEventCallCount++
			if txFailedEventCallCount == testTxCount {
				allTestTxDiscarded <- struct{}{}
			}
		}
	})

	// this call blocks, and should return when DiscardQueuedTransaction() for a given tx id is called
	sendTx := func() {
		txHashCheck, err := statusAPI.SendTransaction(context.TODO(), common.SendTxArgs{
			From:  common.FromAddress(TestConfig.Account1.Address),
			To:    common.ToAddress(TestConfig.Account2.Address),
			Value: (*hexutil.Big)(big.NewInt(1000000000000)),
		})
		if err != txqueue.ErrQueuedTxDiscarded {
			t.Errorf("expected error not thrown: %v", err)
			return
		}

		if !reflect.DeepEqual(txHashCheck, gethcommon.Hash{}) {
			t.Error("transaction returned hash, while it shouldn't")
			return
		}
	}

	// wait for transactions, and discard immediately
	discardTxs := func(txIDStrings string) {
		var parsedIDs []string
		if err := json.Unmarshal([]byte(txIDStrings), &parsedIDs); err != nil {
			t.Error(err)
			return
		}

		parsedIDs = append(parsedIDs, "invalid-tx-id")
		updatedTxIDStrings, _ := json.Marshal(parsedIDs)

		// discard
		discardResultsString := DiscardTransactions(C.CString(string(updatedTxIDStrings)))
		discardResultsStruct := common.DiscardTransactionsResult{}
		if err := json.Unmarshal([]byte(C.GoString(discardResultsString)), &discardResultsStruct); err != nil {
			t.Error(err)
			return
		}
		discardResults := discardResultsStruct.Results

		if len(discardResults) != 1 || discardResults["invalid-tx-id"].Error != txqueue.ErrQueuedTxIDNotFound.Error() {
			t.Errorf("cannot discard txs: %v", discardResults)
			return
		}

		// try completing discarded transaction
		completeResultsString := CompleteTransactions(C.CString(string(updatedTxIDStrings)), C.CString(TestConfig.Account1.Password))
		completeResultsStruct := common.CompleteTransactionsResult{}
		if err := json.Unmarshal([]byte(C.GoString(completeResultsString)), &completeResultsStruct); err != nil {
			t.Error(err)
			return
		}
		completeResults := completeResultsStruct.Results

		if len(completeResults) != (testTxCount + 1) {
			t.Error("unexpected number of errors (call to CompleteTransaction should not succeed)")
		}
		for txID, txResult := range completeResults {
			if txID != txResult.ID {
				t.Errorf("tx id not set in result: expected id is %s", txID)
				return
			}
			if txResult.Error != txqueue.ErrQueuedTxIDNotFound.Error() {
				t.Errorf("invalid error for %s", txResult.Hash)
				return
			}
			if txResult.Hash != zeroHash {
				t.Errorf("invalid hash (expected zero): %s", txResult.Hash)
				return
			}
		}

		time.Sleep(1 * time.Second) // make sure that tx complete signal propagates
		for _, txID := range parsedIDs {
			if txQueue.Has(common.QueuedTxID(txID)) {
				t.Errorf("txqueue should not have test tx at this point (it should be discarded): %s", txID)
				return
			}
		}
	}
	go func() {
		var txIDStrings []string
		for i := 0; i < testTxCount; i++ {
			txIDStrings = append(txIDStrings, <-txIDs)
		}

		txIDJSON, _ := json.Marshal(txIDStrings)
		discardTxs(string(txIDJSON))
	}()

	// send multiple transactions
	for i := 0; i < testTxCount; i++ {
		go sendTx()
	}

	select {
	case <-allTestTxDiscarded:
		// pass
	case <-time.After(20 * time.Second):
		t.Error("test timed out")
		return false
	}

	if txQueue.Count() != 0 {
		t.Error("tx queue must be empty at this point")
		return false
	}

	return true
}

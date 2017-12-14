// +build e2e_test

// This is a file with e2e tests for C bindings written in library.go.
// As a CGO file, it can't have `_test.go` suffix as it's not allowed by Go.
// At the same time, we don't want this file to be included in the binaries.
// This is why `e2e_test` tag was introduced. Without it, this file is excluded
// from the build. Providing this tag will include this file into the build
// and that's what is done while running e2e tests for `lib/` package.

package main

import "C"
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core"
	gethparams "github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"

	"github.com/status-im/status-go/geth/common"
	"github.com/status-im/status-go/geth/params"
	"github.com/status-im/status-go/geth/signal"
	"github.com/status-im/status-go/geth/txqueue"
	"github.com/status-im/status-go/static"
	. "github.com/status-im/status-go/testing" //nolint: golint
)

const zeroHash = "0x0000000000000000000000000000000000000000000000000000000000000000"

var testChainDir string
var nodeConfigJSON string

func init() {
	testChainDir = filepath.Join(TestDataDir, TestNetworkNames[GetNetworkID()])

	nodeConfigJSON = `{
	"NetworkId": ` + strconv.Itoa(GetNetworkID()) + `,
	"DataDir": "` + testChainDir + `",
	"HTTPPort": ` + strconv.Itoa(TestConfig.Node.HTTPPort) + `,
	"WSPort": ` + strconv.Itoa(TestConfig.Node.WSPort) + `,
	"LogLevel": "INFO"
}`
}

// nolint: deadcode
func testExportedAPI(t *testing.T, done chan struct{}) {
	<-startTestNode(t)
	defer func() {
		done <- struct{}{}
	}()

	// prepare accounts
	testKeyDir := filepath.Join(testChainDir, "keystore")
	if err := common.ImportTestAccount(testKeyDir, GetAccount1PKFile()); err != nil {
		panic(err)
	}
	if err := common.ImportTestAccount(testKeyDir, GetAccount2PKFile()); err != nil {
		panic(err)
	}

	// FIXME(tiabc): All of that is done because usage of cgo is not supported in tests.
	// Probably, there should be a cleaner way, for example, test cgo bindings in e2e tests
	// separately from other internal tests.
	// FIXME(@jekamas): ATTENTION! this tests depends on each other!
	tests := []struct {
		name string
		fn   func(t *testing.T) bool
	}{
		{
			"check default configuration",
			testGetDefaultConfig,
		},
		{
			"stop/resume node",
			testStopResumeNode,
		},
		{
			"call RPC on in-proc handler",
			testCallRPC,
		},
		{
			"verify account password",
			testVerifyAccountPassword,
		},
		{
			"account select/login",
			testAccountSelect,
		},
		{
			"account logout",
			testAccountLogout,
		},
		{
			"complete single queued transaction",
			testCompleteTransaction,
		},
		{
			"test complete multiple queued transactions",
			testCompleteMultipleQueuedTransactions,
		},
		{
			"discard single queued transaction",
			testDiscardTransaction,
		},
		{
			"test discard multiple queued transactions",
			testDiscardMultipleQueuedTransactions,
		},
		{
			"test jail invalid initialization",
			testJailInitInvalid,
		},
		{
			"test jail invalid parse",
			testJailParseInvalid,
		},
		{
			"test jail initialization",
			testJailInit,
		},
		{
			"test jailed calls",
			testJailFunctionCall,
		},
		{
			"test ExecuteJS",
			testExecuteJS,
		},
		{
			"test deprecated Parse",
			testJailParseDeprecated,
		},
	}

	for _, test := range tests {
		t.Logf("=== RUN   %s", test.name)
		if ok := test.fn(t); !ok {
			t.Logf("=== FAILED   %s", test.name)
			break
		}
	}
}

func testVerifyAccountPassword(t *testing.T) bool {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "accounts")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir) // nolint: errcheck

	if err = common.ImportTestAccount(tmpDir, GetAccount1PKFile()); err != nil {
		t.Fatal(err)
	}
	if err = common.ImportTestAccount(tmpDir, GetAccount2PKFile()); err != nil {
		t.Fatal(err)
	}

	// rename account file (to see that file's internals reviewed, when locating account key)
	accountFilePathOriginal := filepath.Join(tmpDir, GetAccount1PKFile())
	accountFilePath := filepath.Join(tmpDir, "foo"+TestConfig.Account1.Address+"bar.pk")
	if err := os.Rename(accountFilePathOriginal, accountFilePath); err != nil {
		t.Fatal(err)
	}

	response := common.APIResponse{}
	rawResponse := VerifyAccountPassword(
		C.CString(tmpDir),
		C.CString(TestConfig.Account1.Address),
		C.CString(TestConfig.Account1.Password))

	if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &response); err != nil {
		t.Errorf("cannot decode response (%s): %v", C.GoString(rawResponse), err)
		return false
	}
	if response.Error != "" {
		t.Errorf("unexpected error: %s", response.Error)
		return false
	}

	return true
}

func testGetDefaultConfig(t *testing.T) bool {
	networks := []struct {
		chainID        int
		refChainConfig *gethparams.ChainConfig
	}{
		{params.MainNetworkID, gethparams.MainnetChainConfig},
		{params.RopstenNetworkID, gethparams.TestnetChainConfig},
		{params.RinkebyNetworkID, gethparams.RinkebyChainConfig},
		// TODO(tiabc): The same for params.StatusChainNetworkID
	}
	for i := range networks {
		network := networks[i]

		t.Run(fmt.Sprintf("networkID=%d", network.chainID), func(t *testing.T) {
			var (
				nodeConfig  = params.NodeConfig{}
				rawResponse = GenerateConfig(C.CString("/tmp/data-folder"), C.int(network.chainID), 1)
			)
			if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &nodeConfig); err != nil {
				t.Errorf("cannot decode response (%s): %v", C.GoString(rawResponse), err)
			}

			genesis := new(core.Genesis)
			if err := json.Unmarshal([]byte(nodeConfig.LightEthConfig.Genesis), genesis); err != nil {
				t.Error(err)
			}

			require.Equal(t, network.refChainConfig, genesis.Config)
		})
	}
	return true
}

//@TODO(adam): quarantined this test until it uses a different directory.
//nolint: deadcode
func testResetChainData(t *testing.T) bool {
	t.Skip()

	resetChainDataResponse := common.APIResponse{}
	rawResponse := ResetChainData()

	if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &resetChainDataResponse); err != nil {
		t.Errorf("cannot decode ResetChainData response (%s): %v", C.GoString(rawResponse), err)
		return false
	}
	if resetChainDataResponse.Error != "" {
		t.Errorf("unexpected error: %s", resetChainDataResponse.Error)
		return false
	}

	EnsureNodeSync(statusAPI.NodeManager())
	testCompleteTransaction(t)

	return true
}

func testStopResumeNode(t *testing.T) bool { //nolint: gocyclo
	// to make sure that we start with empty account (which might have gotten populated during previous tests)
	if err := statusAPI.Logout(); err != nil {
		t.Fatal(err)
	}

	whisperService, err := statusAPI.NodeManager().WhisperService()
	if err != nil {
		t.Errorf("whisper service not running: %v", err)
	}

	// create an account
	accountInfo, err := statusAPI.CreateAccount(TestConfig.Account1.Password)

	address1 := accountInfo.Address
	pubKey1 := accountInfo.PubKey

	if err != nil {
		t.Errorf("could not create account: %v", err)
		return false
	}
	t.Logf("account created: {address: %s, key: %s}", address1, pubKey1)

	// make sure that identity is not (yet injected)
	if whisperService.HasKeyPair(pubKey1) {
		t.Error("identity already present in whisper")
	}

	// select account
	loginResponse := common.APIResponse{}
	rawResponse := Login(C.CString(address1), C.CString(TestConfig.Account1.Password))

	if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &loginResponse); err != nil {
		t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
		return false
	}

	if loginResponse.Error != "" {
		t.Errorf("could not select account: %v", err)
		return false
	}
	if !whisperService.HasKeyPair(pubKey1) {
		t.Errorf("identity not injected into whisper: %v", err)
	}

	// stop and resume node, then make sure that selected account is still selected
	// nolint: dupl
	stopNodeFn := func() bool {
		response := common.APIResponse{}
		// FIXME(tiabc): Implement https://github.com/status-im/status-go/issues/254 to avoid
		// 9-sec timeout below after stopping the node.
		rawResponse = StopNode()

		if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &response); err != nil {
			t.Errorf("cannot decode StopNode response (%s): %v", C.GoString(rawResponse), err)
			return false
		}
		if response.Error != "" {
			t.Errorf("unexpected error: %s", response.Error)
			return false
		}

		return true
	}

	// nolint: dupl
	resumeNodeFn := func() bool {
		response := common.APIResponse{}
		// FIXME(tiabc): Implement https://github.com/status-im/status-go/issues/254 to avoid
		// 10-sec timeout below after resuming the node.
		rawResponse = StartNode(C.CString(nodeConfigJSON))

		if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &response); err != nil {
			t.Errorf("cannot decode StartNode response (%s): %v", C.GoString(rawResponse), err)
			return false
		}
		if response.Error != "" {
			t.Errorf("unexpected error: %s", response.Error)
			return false
		}

		return true
	}

	if !stopNodeFn() {
		return false
	}

	time.Sleep(9 * time.Second) // allow to stop

	if !resumeNodeFn() {
		return false
	}

	time.Sleep(10 * time.Second) // allow to start (instead of using blocking version of start, of filter event)

	// now, verify that we still have account logged in
	whisperService, err = statusAPI.NodeManager().WhisperService()
	if err != nil {
		t.Errorf("whisper service not running: %v", err)
	}
	if !whisperService.HasKeyPair(pubKey1) {
		t.Errorf("identity evicted from whisper on node restart: %v", err)
	}

	// additionally, let's complete transaction (just to make sure that node lives through pause/resume w/o issues)
	testCompleteTransaction(t)

	return true
}

func testCallRPC(t *testing.T) bool {
	expected := `{"jsonrpc":"2.0","id":64,"result":"0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"}`
	rawResponse := CallRPC(C.CString(`{"jsonrpc":"2.0","method":"web3_sha3","params":["0x68656c6c6f20776f726c64"],"id":64}`))
	received := C.GoString(rawResponse)
	if expected != received {
		t.Errorf("unexpected response: expected: %v, got: %v", expected, received)
		return false
	}

	return true
}

func testAccountSelect(t *testing.T) bool { //nolint: gocyclo
	// test to see if the account was injected in whisper
	whisperService, err := statusAPI.NodeManager().WhisperService()
	if err != nil {
		t.Errorf("whisper service not running: %v", err)
	}

	// create an account
	accountInfo1, err := statusAPI.CreateAccount(TestConfig.Account1.Password)
	address1 := accountInfo1.Address
	pubKey1 := accountInfo1.PubKey

	if err != nil {
		t.Errorf("could not create account: %v", err)
		return false
	}
	t.Logf("Account created: {address: %s, key: %s}", address1, pubKey1)

	accountInfo2, err := statusAPI.CreateAccount(TestConfig.Account1.Password)
	address2 := accountInfo2.Address
	pubKey2 := accountInfo2.PubKey

	if err != nil {
		t.Error("Test failed: could not create account")
		return false
	}
	t.Logf("Account created: {address: %s, key: %s}", address2, pubKey2)

	// make sure that identity is not (yet injected)
	if whisperService.HasKeyPair(pubKey1) {
		t.Error("identity already present in whisper")
	}

	// try selecting with wrong password
	loginResponse := common.APIResponse{}
	rawResponse := Login(C.CString(address1), C.CString("wrongPassword"))

	if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &loginResponse); err != nil {
		t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
		return false
	}

	if loginResponse.Error == "" {
		t.Error("select account is expected to throw error: wrong password used")
		return false
	}

	loginResponse = common.APIResponse{}
	rawResponse = Login(C.CString(address1), C.CString(TestConfig.Account1.Password))

	if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &loginResponse); err != nil {
		t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
		return false
	}

	if loginResponse.Error != "" {
		t.Errorf("Test failed: could not select account: %v", err)
		return false
	}
	if !whisperService.HasKeyPair(pubKey1) {
		t.Errorf("identity not injected into whisper: %v", err)
	}

	// select another account, make sure that previous account is wiped out from Whisper cache
	if whisperService.HasKeyPair(pubKey2) {
		t.Error("identity already present in whisper")
	}

	loginResponse = common.APIResponse{}
	rawResponse = Login(C.CString(address2), C.CString(TestConfig.Account1.Password))

	if err = json.Unmarshal([]byte(C.GoString(rawResponse)), &loginResponse); err != nil {
		t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
		return false
	}

	if loginResponse.Error != "" {
		t.Errorf("Test failed: could not select account: %v", loginResponse.Error)
		return false
	}
	if !whisperService.HasKeyPair(pubKey2) {
		t.Errorf("identity not injected into whisper: %v", err)
	}
	if whisperService.HasKeyPair(pubKey1) {
		t.Error("identity should be removed, but it is still present in whisper")
	}

	return true
}

func testAccountLogout(t *testing.T) bool {
	whisperService, err := statusAPI.NodeManager().WhisperService()
	if err != nil {
		t.Errorf("whisper service not running: %v", err)
		return false
	}

	// create an account
	accountInfo, err := statusAPI.CreateAccount(TestConfig.Account1.Password)
	address := accountInfo.Address
	pubKey := accountInfo.PubKey

	if err != nil {
		t.Errorf("could not create account: %v", err)
		return false
	}

	// make sure that identity doesn't exist (yet) in Whisper
	if whisperService.HasKeyPair(pubKey) {
		t.Error("identity already present in whisper")
		return false
	}

	// select/login
	err = statusAPI.SelectAccount(address, TestConfig.Account1.Password)
	if err != nil {
		t.Errorf("Test failed: could not select account: %v", err)
		return false
	}
	if !whisperService.HasKeyPair(pubKey) {
		t.Error("identity not injected into whisper")
		return false
	}

	logoutResponse := common.APIResponse{}
	rawResponse := Logout()

	if err := json.Unmarshal([]byte(C.GoString(rawResponse)), &logoutResponse); err != nil {
		t.Errorf("cannot decode RecoverAccount response (%s): %v", C.GoString(rawResponse), err)
		return false
	}

	if logoutResponse.Error != "" {
		t.Errorf("cannot logout: %v", logoutResponse.Error)
		return false
	}

	// now, logout and check if identity is removed indeed
	if whisperService.HasKeyPair(pubKey) {
		t.Error("identity not cleared from whisper")
		return false
	}

	return true
}

func testJailInitInvalid(t *testing.T) bool {
	// Arrange.
	initInvalidCode := `
	var _status_catalog = {
		foo: 'bar'
	`

	// Act.
	InitJail(C.CString(initInvalidCode))
	response := C.GoString(CreateAndInitCell(C.CString("CHAT_ID_INIT_INVALID_TEST"), C.CString(``)))

	// Assert.
	expectedSubstr := `"error":"(anonymous): Line 4:3 Unexpected identifier`
	if !strings.Contains(response, expectedSubstr) {
		t.Errorf("unexpected response, didn't find '%s' in '%s'", expectedSubstr, response)
		return false
	}
	return true
}

func testJailParseInvalid(t *testing.T) bool {
	// Arrange.
	initCode := `
	var _status_catalog = {
		foo: 'bar'
	};
	`

	// Act.
	InitJail(C.CString(initCode))
	extraInvalidCode := `
	var extraFunc = function (x) {
	  return x * x;
	`
	response := C.GoString(CreateAndInitCell(C.CString("CHAT_ID_PARSE_INVALID_TEST"), C.CString(extraInvalidCode)))

	// Assert.
	expectedResponse := `{"error":"(anonymous): Line 4:2 Unexpected end of input (and 1 more errors)"}`
	if expectedResponse != response {
		t.Errorf("unexpected response, expected: %v, got: %v", expectedResponse, response)
		return false
	}
	return true
}

func testJailInit(t *testing.T) bool {
	initCode := `
	var _status_catalog = {
		foo: 'bar'
	};
	`
	InitJail(C.CString(initCode))

	extraCode := `
	var extraFunc = function (x) {
	  return x * x;
	};
	`
	rawResponse := CreateAndInitCell(C.CString("CHAT_ID_INIT_TEST"), C.CString(extraCode))
	parsedResponse := C.GoString(rawResponse)

	expectedResponse := `{"result": {"foo":"bar"}}`

	if !reflect.DeepEqual(expectedResponse, parsedResponse) {
		t.Error("expected output not returned from jail.CreateAndInitCell()")
		return false
	}

	t.Logf("jail inited and parsed: %s", parsedResponse)

	return true
}

func testJailParseDeprecated(t *testing.T) bool {
	initCode := `
		var _status_catalog = {
			foo: 'bar'
		};
	`
	InitJail(C.CString(initCode))

	extraCode := `
		var extraFunc = function (x) {
			return x * x;
		};
	`
	rawResponse := Parse(C.CString("CHAT_ID_PARSE_TEST"), C.CString(extraCode))
	parsedResponse := C.GoString(rawResponse)
	expectedResponse := `{"result": {"foo":"bar"}}`
	if !reflect.DeepEqual(expectedResponse, parsedResponse) {
		t.Error("expected output not returned from Parse()")
		return false
	}

	// cell already exists but Parse should not complain
	rawResponse = Parse(C.CString("CHAT_ID_PARSE_TEST"), C.CString(extraCode))
	parsedResponse = C.GoString(rawResponse)
	expectedResponse = `{"result": {"foo":"bar"}}`
	if !reflect.DeepEqual(expectedResponse, parsedResponse) {
		t.Error("expected output not returned from Parse()")
		return false
	}

	// test extraCode
	rawResponse = ExecuteJS(C.CString("CHAT_ID_PARSE_TEST"), C.CString(`extraFunc(2)`))
	parsedResponse = C.GoString(rawResponse)
	expectedResponse = `4`
	if !reflect.DeepEqual(expectedResponse, parsedResponse) {
		t.Error("expected output not returned from ExecuteJS()")
		return false
	}

	return true
}

func testJailFunctionCall(t *testing.T) bool {
	InitJail(C.CString(""))

	// load Status JS and add test command to it
	statusJS := string(static.MustAsset("testdata/jail/status.js")) + `;
	_status_catalog.commands["testCommand"] = function (params) {
		return params.val * params.val;
	};`
	CreateAndInitCell(C.CString("CHAT_ID_CALL_TEST"), C.CString(statusJS))

	// call with wrong chat id
	rawResponse := Call(C.CString("CHAT_IDNON_EXISTENT"), C.CString(""), C.CString(""))
	parsedResponse := C.GoString(rawResponse)
	expectedError := `{"error":"cell 'CHAT_IDNON_EXISTENT' not found"}`
	if parsedResponse != expectedError {
		t.Errorf("expected error is not returned: expected %s, got %s", expectedError, parsedResponse)
		return false
	}

	// call extraFunc()
	rawResponse = Call(C.CString("CHAT_ID_CALL_TEST"), C.CString(`["commands", "testCommand"]`), C.CString(`{"val": 12}`))
	parsedResponse = C.GoString(rawResponse)
	expectedResponse := `{"result": 144}`
	if parsedResponse != expectedResponse {
		t.Errorf("expected response is not returned: expected %s, got %s", expectedResponse, parsedResponse)
		return false
	}

	t.Logf("jailed method called: %s", parsedResponse)

	return true
}

func testExecuteJS(t *testing.T) bool {
	InitJail(C.CString(""))

	// cell does not exist
	response := C.GoString(ExecuteJS(C.CString("CHAT_ID_EXECUTE_TEST"), C.CString("('some string')")))
	expectedResponse := `{"error":"cell 'CHAT_ID_EXECUTE_TEST' not found"}`
	if response != expectedResponse {
		t.Errorf("expected '%s' but got '%s'", expectedResponse, response)
		return false
	}

	CreateAndInitCell(C.CString("CHAT_ID_EXECUTE_TEST"), C.CString(`var obj = { status: true }`))

	// cell does not exist
	response = C.GoString(ExecuteJS(C.CString("CHAT_ID_EXECUTE_TEST"), C.CString(`JSON.stringify(obj)`)))
	expectedResponse = `{"status":true}`
	if response != expectedResponse {
		t.Errorf("expected '%s' but got '%s'", expectedResponse, response)
		return false
	}

	return true
}

func startTestNode(t *testing.T) <-chan struct{} {
	testDir := filepath.Join(TestDataDir, TestNetworkNames[GetNetworkID()])

	syncRequired := false
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		syncRequired = true
	}

	// inject test accounts
	testKeyDir := filepath.Join(testDir, "keystore")
	if err := common.ImportTestAccount(testKeyDir, GetAccount1PKFile()); err != nil {
		panic(err)
	}
	if err := common.ImportTestAccount(testKeyDir, GetAccount2PKFile()); err != nil {
		panic(err)
	}

	waitForNodeStart := make(chan struct{}, 1)
	signal.SetDefaultNodeNotificationHandler(func(jsonEvent string) {
		t.Log(jsonEvent)
		var envelope signal.Envelope
		if err := json.Unmarshal([]byte(jsonEvent), &envelope); err != nil {
			t.Errorf("cannot unmarshal event's JSON: %s", jsonEvent)
			return
		}
		if envelope.Type == signal.EventNodeCrashed {
			signal.TriggerDefaultNodeNotificationHandler(jsonEvent)
			return
		}

		if envelope.Type == txqueue.EventTransactionQueued {
		}
		if envelope.Type == signal.EventNodeStarted {
			t.Log("Node started, but we wait till it be ready")
		}
		if envelope.Type == signal.EventNodeReady {
			// sync
			if syncRequired {
				t.Logf("Sync is required")
				EnsureNodeSync(statusAPI.NodeManager())
			} else {
				time.Sleep(5 * time.Second)
			}

			// now we can proceed with tests
			waitForNodeStart <- struct{}{}
		}
	})

	go func() {
		response := StartNode(C.CString(nodeConfigJSON))
		responseErr := common.APIResponse{}

		if err := json.Unmarshal([]byte(C.GoString(response)), &responseErr); err != nil {
			panic(err)
		}
		if responseErr.Error != "" {
			panic("cannot start node: " + responseErr.Error)
		}
	}()

	return waitForNodeStart
}

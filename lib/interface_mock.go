// Code generated by MockGen. DO NOT EDIT.
// Source: lib/interface.go

// Package main is a generated GoMock package.
package main

import (
	context "context"
	go_fcm "github.com/NaySoftware/go-fcm"
	keystore "github.com/ethereum/go-ethereum/accounts/keystore"
	common "github.com/ethereum/go-ethereum/common"
	gomock "github.com/golang/mock/gomock"
	common0 "github.com/status-im/status-go/geth/common"
	params "github.com/status-im/status-go/geth/params"
	reflect "reflect"
)

// MocklibStatusAPI is a mock of libStatusAPI interface
type MocklibStatusAPI struct {
	ctrl     *gomock.Controller
	recorder *MocklibStatusAPIMockRecorder
}

// MocklibStatusAPIMockRecorder is the mock recorder for MocklibStatusAPI
type MocklibStatusAPIMockRecorder struct {
	mock *MocklibStatusAPI
}

// NewMocklibStatusAPI creates a new mock instance
func NewMocklibStatusAPI(ctrl *gomock.Controller) *MocklibStatusAPI {
	mock := &MocklibStatusAPI{ctrl: ctrl}
	mock.recorder = &MocklibStatusAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocklibStatusAPI) EXPECT() *MocklibStatusAPIMockRecorder {
	return m.recorder
}

// JailCall mocks base method
func (m *MocklibStatusAPI) JailCall(chatID, this, args string) string {
	ret := m.ctrl.Call(m, "JailCall", chatID, this, args)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailCall indicates an expected call of JailCall
func (mr *MocklibStatusAPIMockRecorder) JailCall(chatID, this, args interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailCall", reflect.TypeOf((*MocklibStatusAPI)(nil).JailCall), chatID, this, args)
}

// JailExecute mocks base method
func (m *MocklibStatusAPI) JailExecute(chatID, code string) string {
	ret := m.ctrl.Call(m, "JailExecute", chatID, code)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailExecute indicates an expected call of JailExecute
func (mr *MocklibStatusAPIMockRecorder) JailExecute(chatID, code interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailExecute", reflect.TypeOf((*MocklibStatusAPI)(nil).JailExecute), chatID, code)
}

// SetJailBaseJS mocks base method
func (m *MocklibStatusAPI) SetJailBaseJS(js string) {
	m.ctrl.Call(m, "SetJailBaseJS", js)
}

// SetJailBaseJS indicates an expected call of SetJailBaseJS
func (mr *MocklibStatusAPIMockRecorder) SetJailBaseJS(js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetJailBaseJS", reflect.TypeOf((*MocklibStatusAPI)(nil).SetJailBaseJS), js)
}

// JailParse mocks base method
func (m *MocklibStatusAPI) JailParse(chatID, js string) string {
	ret := m.ctrl.Call(m, "JailParse", chatID, js)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailParse indicates an expected call of JailParse
func (mr *MocklibStatusAPIMockRecorder) JailParse(chatID, js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailParse", reflect.TypeOf((*MocklibStatusAPI)(nil).JailParse), chatID, js)
}

// CreateAndInitCell mocks base method
func (m *MocklibStatusAPI) CreateAndInitCell(chatID, js string) string {
	ret := m.ctrl.Call(m, "CreateAndInitCell", chatID, js)
	ret0, _ := ret[0].(string)
	return ret0
}

// CreateAndInitCell indicates an expected call of CreateAndInitCell
func (mr *MocklibStatusAPIMockRecorder) CreateAndInitCell(chatID, js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAndInitCell", reflect.TypeOf((*MocklibStatusAPI)(nil).CreateAndInitCell), chatID, js)
}

// CreateAccount mocks base method
func (m *MocklibStatusAPI) CreateAccount(password string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "CreateAccount", password)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAccount indicates an expected call of CreateAccount
func (mr *MocklibStatusAPIMockRecorder) CreateAccount(password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccount", reflect.TypeOf((*MocklibStatusAPI)(nil).CreateAccount), password)
}

// CreateChildAccount mocks base method
func (m *MocklibStatusAPI) CreateChildAccount(parentAddress, password string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "CreateChildAccount", parentAddress, password)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateChildAccount indicates an expected call of CreateChildAccount
func (mr *MocklibStatusAPIMockRecorder) CreateChildAccount(parentAddress, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateChildAccount", reflect.TypeOf((*MocklibStatusAPI)(nil).CreateChildAccount), parentAddress, password)
}

// RecoverAccount mocks base method
func (m *MocklibStatusAPI) RecoverAccount(password, mnemonic string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "RecoverAccount", password, mnemonic)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RecoverAccount indicates an expected call of RecoverAccount
func (mr *MocklibStatusAPIMockRecorder) RecoverAccount(password, mnemonic interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecoverAccount", reflect.TypeOf((*MocklibStatusAPI)(nil).RecoverAccount), password, mnemonic)
}

// VerifyAccountPassword mocks base method
func (m *MocklibStatusAPI) VerifyAccountPassword(keyStoreDir, address, password string) (*keystore.Key, error) {
	ret := m.ctrl.Call(m, "VerifyAccountPassword", keyStoreDir, address, password)
	ret0, _ := ret[0].(*keystore.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyAccountPassword indicates an expected call of VerifyAccountPassword
func (mr *MocklibStatusAPIMockRecorder) VerifyAccountPassword(keyStoreDir, address, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyAccountPassword", reflect.TypeOf((*MocklibStatusAPI)(nil).VerifyAccountPassword), keyStoreDir, address, password)
}

// SelectAccount mocks base method
func (m *MocklibStatusAPI) SelectAccount(address, password string) error {
	ret := m.ctrl.Call(m, "SelectAccount", address, password)
	ret0, _ := ret[0].(error)
	return ret0
}

// SelectAccount indicates an expected call of SelectAccount
func (mr *MocklibStatusAPIMockRecorder) SelectAccount(address, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SelectAccount", reflect.TypeOf((*MocklibStatusAPI)(nil).SelectAccount), address, password)
}

// Logout mocks base method
func (m *MocklibStatusAPI) Logout() error {
	ret := m.ctrl.Call(m, "Logout")
	ret0, _ := ret[0].(error)
	return ret0
}

// Logout indicates an expected call of Logout
func (mr *MocklibStatusAPIMockRecorder) Logout() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logout", reflect.TypeOf((*MocklibStatusAPI)(nil).Logout))
}

// CompleteTransaction mocks base method
func (m *MocklibStatusAPI) CompleteTransaction(id common0.QueuedTxID, password string) (common0.CompleteTransactionResult, error) {
	ret := m.ctrl.Call(m, "CompleteTransaction", id, password)
	ret0, _ := ret[0].(common0.CompleteTransactionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CompleteTransaction indicates an expected call of CompleteTransaction
func (mr *MocklibStatusAPIMockRecorder) CompleteTransaction(id, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompleteTransaction", reflect.TypeOf((*MocklibStatusAPI)(nil).CompleteTransaction), id, password)
}

// CompleteTransactions mocks base method
func (m *MocklibStatusAPI) CompleteTransactions(ids []common0.QueuedTxID, password string) (common0.CompleteTransactionsResult, map[common0.QueuedTxID]error) {
	ret := m.ctrl.Call(m, "CompleteTransactions", ids, password)
	ret0, _ := ret[0].(common0.CompleteTransactionsResult)
	ret1, _ := ret[1].(map[common0.QueuedTxID]error)
	return ret0, ret1
}

// CompleteTransactions indicates an expected call of CompleteTransactions
func (mr *MocklibStatusAPIMockRecorder) CompleteTransactions(ids, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompleteTransactions", reflect.TypeOf((*MocklibStatusAPI)(nil).CompleteTransactions), ids, password)
}

// DiscardTransaction mocks base method
func (m *MocklibStatusAPI) DiscardTransaction(id common0.QueuedTxID) (common0.DiscardTransactionResult, error) {
	ret := m.ctrl.Call(m, "DiscardTransaction", id)
	ret0, _ := ret[0].(common0.DiscardTransactionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DiscardTransaction indicates an expected call of DiscardTransaction
func (mr *MocklibStatusAPIMockRecorder) DiscardTransaction(id interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DiscardTransaction", reflect.TypeOf((*MocklibStatusAPI)(nil).DiscardTransaction), id)
}

// DiscardTransactions mocks base method
func (m *MocklibStatusAPI) DiscardTransactions(ids []common0.QueuedTxID) (common0.DiscardTransactionsResult, map[common0.QueuedTxID]error) {
	ret := m.ctrl.Call(m, "DiscardTransactions", ids)
	ret0, _ := ret[0].(common0.DiscardTransactionsResult)
	ret1, _ := ret[1].(map[common0.QueuedTxID]error)
	return ret0, ret1
}

// DiscardTransactions indicates an expected call of DiscardTransactions
func (mr *MocklibStatusAPIMockRecorder) DiscardTransactions(ids interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DiscardTransactions", reflect.TypeOf((*MocklibStatusAPI)(nil).DiscardTransactions), ids)
}

// TxQueueManager mocks base method
func (m *MocklibStatusAPI) TxQueueManager() common0.TxQueueManager {
	ret := m.ctrl.Call(m, "TxQueueManager")
	ret0, _ := ret[0].(common0.TxQueueManager)
	return ret0
}

// TxQueueManager indicates an expected call of TxQueueManager
func (mr *MocklibStatusAPIMockRecorder) TxQueueManager() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TxQueueManager", reflect.TypeOf((*MocklibStatusAPI)(nil).TxQueueManager))
}

// SendTransaction mocks base method
func (m *MocklibStatusAPI) SendTransaction(ctx context.Context, args common0.SendTxArgs) (common.Hash, error) {
	ret := m.ctrl.Call(m, "SendTransaction", ctx, args)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendTransaction indicates an expected call of SendTransaction
func (mr *MocklibStatusAPIMockRecorder) SendTransaction(ctx, args interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendTransaction", reflect.TypeOf((*MocklibStatusAPI)(nil).SendTransaction), ctx, args)
}

// NodeManager mocks base method
func (m *MocklibStatusAPI) NodeManager() common0.NodeManager {
	ret := m.ctrl.Call(m, "NodeManager")
	ret0, _ := ret[0].(common0.NodeManager)
	return ret0
}

// NodeManager indicates an expected call of NodeManager
func (mr *MocklibStatusAPIMockRecorder) NodeManager() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NodeManager", reflect.TypeOf((*MocklibStatusAPI)(nil).NodeManager))
}

// ValidateJSONConfig mocks base method
func (m *MocklibStatusAPI) ValidateJSONConfig(configJSON string) common0.APIDetailedResponse {
	ret := m.ctrl.Call(m, "ValidateJSONConfig", configJSON)
	ret0, _ := ret[0].(common0.APIDetailedResponse)
	return ret0
}

// ValidateJSONConfig indicates an expected call of ValidateJSONConfig
func (mr *MocklibStatusAPIMockRecorder) ValidateJSONConfig(configJSON interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateJSONConfig", reflect.TypeOf((*MocklibStatusAPI)(nil).ValidateJSONConfig), configJSON)
}

// StartNodeAsync mocks base method
func (m *MocklibStatusAPI) StartNodeAsync(config *params.NodeConfig) (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "StartNodeAsync", config)
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartNodeAsync indicates an expected call of StartNodeAsync
func (mr *MocklibStatusAPIMockRecorder) StartNodeAsync(config interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartNodeAsync", reflect.TypeOf((*MocklibStatusAPI)(nil).StartNodeAsync), config)
}

// StopNodeAsync mocks base method
func (m *MocklibStatusAPI) StopNodeAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "StopNodeAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StopNodeAsync indicates an expected call of StopNodeAsync
func (mr *MocklibStatusAPIMockRecorder) StopNodeAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopNodeAsync", reflect.TypeOf((*MocklibStatusAPI)(nil).StopNodeAsync))
}

// RestartNodeAsync mocks base method
func (m *MocklibStatusAPI) RestartNodeAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "RestartNodeAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RestartNodeAsync indicates an expected call of RestartNodeAsync
func (mr *MocklibStatusAPIMockRecorder) RestartNodeAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestartNodeAsync", reflect.TypeOf((*MocklibStatusAPI)(nil).RestartNodeAsync))
}

// ResetChainDataAsync mocks base method
func (m *MocklibStatusAPI) ResetChainDataAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "ResetChainDataAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResetChainDataAsync indicates an expected call of ResetChainDataAsync
func (mr *MocklibStatusAPIMockRecorder) ResetChainDataAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResetChainDataAsync", reflect.TypeOf((*MocklibStatusAPI)(nil).ResetChainDataAsync))
}

// CallRPC mocks base method
func (m *MocklibStatusAPI) CallRPC(inputJSON string) string {
	ret := m.ctrl.Call(m, "CallRPC", inputJSON)
	ret0, _ := ret[0].(string)
	return ret0
}

// CallRPC indicates an expected call of CallRPC
func (mr *MocklibStatusAPIMockRecorder) CallRPC(inputJSON interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallRPC", reflect.TypeOf((*MocklibStatusAPI)(nil).CallRPC), inputJSON)
}

// Notify mocks base method
func (m *MocklibStatusAPI) Notify(token string) string {
	ret := m.ctrl.Call(m, "Notify", token)
	ret0, _ := ret[0].(string)
	return ret0
}

// Notify indicates an expected call of Notify
func (mr *MocklibStatusAPIMockRecorder) Notify(token interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Notify", reflect.TypeOf((*MocklibStatusAPI)(nil).Notify), token)
}

// NotifyUsers mocks base method
func (m *MocklibStatusAPI) NotifyUsers(message string, payload go_fcm.NotificationPayload, tokens ...string) error {
	varargs := []interface{}{message, payload}
	for _, a := range tokens {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "NotifyUsers", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// NotifyUsers indicates an expected call of NotifyUsers
func (mr *MocklibStatusAPIMockRecorder) NotifyUsers(message, payload interface{}, tokens ...interface{}) *gomock.Call {
	varargs := append([]interface{}{message, payload}, tokens...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NotifyUsers", reflect.TypeOf((*MocklibStatusAPI)(nil).NotifyUsers), varargs...)
}

// MockjailAPI is a mock of jailAPI interface
type MockjailAPI struct {
	ctrl     *gomock.Controller
	recorder *MockjailAPIMockRecorder
}

// MockjailAPIMockRecorder is the mock recorder for MockjailAPI
type MockjailAPIMockRecorder struct {
	mock *MockjailAPI
}

// NewMockjailAPI creates a new mock instance
func NewMockjailAPI(ctrl *gomock.Controller) *MockjailAPI {
	mock := &MockjailAPI{ctrl: ctrl}
	mock.recorder = &MockjailAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockjailAPI) EXPECT() *MockjailAPIMockRecorder {
	return m.recorder
}

// JailCall mocks base method
func (m *MockjailAPI) JailCall(chatID, this, args string) string {
	ret := m.ctrl.Call(m, "JailCall", chatID, this, args)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailCall indicates an expected call of JailCall
func (mr *MockjailAPIMockRecorder) JailCall(chatID, this, args interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailCall", reflect.TypeOf((*MockjailAPI)(nil).JailCall), chatID, this, args)
}

// JailExecute mocks base method
func (m *MockjailAPI) JailExecute(chatID, code string) string {
	ret := m.ctrl.Call(m, "JailExecute", chatID, code)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailExecute indicates an expected call of JailExecute
func (mr *MockjailAPIMockRecorder) JailExecute(chatID, code interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailExecute", reflect.TypeOf((*MockjailAPI)(nil).JailExecute), chatID, code)
}

// SetJailBaseJS mocks base method
func (m *MockjailAPI) SetJailBaseJS(js string) {
	m.ctrl.Call(m, "SetJailBaseJS", js)
}

// SetJailBaseJS indicates an expected call of SetJailBaseJS
func (mr *MockjailAPIMockRecorder) SetJailBaseJS(js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetJailBaseJS", reflect.TypeOf((*MockjailAPI)(nil).SetJailBaseJS), js)
}

// JailParse mocks base method
func (m *MockjailAPI) JailParse(chatID, js string) string {
	ret := m.ctrl.Call(m, "JailParse", chatID, js)
	ret0, _ := ret[0].(string)
	return ret0
}

// JailParse indicates an expected call of JailParse
func (mr *MockjailAPIMockRecorder) JailParse(chatID, js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "JailParse", reflect.TypeOf((*MockjailAPI)(nil).JailParse), chatID, js)
}

// CreateAndInitCell mocks base method
func (m *MockjailAPI) CreateAndInitCell(chatID, js string) string {
	ret := m.ctrl.Call(m, "CreateAndInitCell", chatID, js)
	ret0, _ := ret[0].(string)
	return ret0
}

// CreateAndInitCell indicates an expected call of CreateAndInitCell
func (mr *MockjailAPIMockRecorder) CreateAndInitCell(chatID, js interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAndInitCell", reflect.TypeOf((*MockjailAPI)(nil).CreateAndInitCell), chatID, js)
}

// MockaccountAPI is a mock of accountAPI interface
type MockaccountAPI struct {
	ctrl     *gomock.Controller
	recorder *MockaccountAPIMockRecorder
}

// MockaccountAPIMockRecorder is the mock recorder for MockaccountAPI
type MockaccountAPIMockRecorder struct {
	mock *MockaccountAPI
}

// NewMockaccountAPI creates a new mock instance
func NewMockaccountAPI(ctrl *gomock.Controller) *MockaccountAPI {
	mock := &MockaccountAPI{ctrl: ctrl}
	mock.recorder = &MockaccountAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockaccountAPI) EXPECT() *MockaccountAPIMockRecorder {
	return m.recorder
}

// CreateAccount mocks base method
func (m *MockaccountAPI) CreateAccount(password string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "CreateAccount", password)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAccount indicates an expected call of CreateAccount
func (mr *MockaccountAPIMockRecorder) CreateAccount(password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccount", reflect.TypeOf((*MockaccountAPI)(nil).CreateAccount), password)
}

// CreateChildAccount mocks base method
func (m *MockaccountAPI) CreateChildAccount(parentAddress, password string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "CreateChildAccount", parentAddress, password)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateChildAccount indicates an expected call of CreateChildAccount
func (mr *MockaccountAPIMockRecorder) CreateChildAccount(parentAddress, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateChildAccount", reflect.TypeOf((*MockaccountAPI)(nil).CreateChildAccount), parentAddress, password)
}

// RecoverAccount mocks base method
func (m *MockaccountAPI) RecoverAccount(password, mnemonic string) (common0.AccountInfo, error) {
	ret := m.ctrl.Call(m, "RecoverAccount", password, mnemonic)
	ret0, _ := ret[0].(common0.AccountInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RecoverAccount indicates an expected call of RecoverAccount
func (mr *MockaccountAPIMockRecorder) RecoverAccount(password, mnemonic interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecoverAccount", reflect.TypeOf((*MockaccountAPI)(nil).RecoverAccount), password, mnemonic)
}

// VerifyAccountPassword mocks base method
func (m *MockaccountAPI) VerifyAccountPassword(keyStoreDir, address, password string) (*keystore.Key, error) {
	ret := m.ctrl.Call(m, "VerifyAccountPassword", keyStoreDir, address, password)
	ret0, _ := ret[0].(*keystore.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyAccountPassword indicates an expected call of VerifyAccountPassword
func (mr *MockaccountAPIMockRecorder) VerifyAccountPassword(keyStoreDir, address, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyAccountPassword", reflect.TypeOf((*MockaccountAPI)(nil).VerifyAccountPassword), keyStoreDir, address, password)
}

// SelectAccount mocks base method
func (m *MockaccountAPI) SelectAccount(address, password string) error {
	ret := m.ctrl.Call(m, "SelectAccount", address, password)
	ret0, _ := ret[0].(error)
	return ret0
}

// SelectAccount indicates an expected call of SelectAccount
func (mr *MockaccountAPIMockRecorder) SelectAccount(address, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SelectAccount", reflect.TypeOf((*MockaccountAPI)(nil).SelectAccount), address, password)
}

// Logout mocks base method
func (m *MockaccountAPI) Logout() error {
	ret := m.ctrl.Call(m, "Logout")
	ret0, _ := ret[0].(error)
	return ret0
}

// Logout indicates an expected call of Logout
func (mr *MockaccountAPIMockRecorder) Logout() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logout", reflect.TypeOf((*MockaccountAPI)(nil).Logout))
}

// MocktransactionAPI is a mock of transactionAPI interface
type MocktransactionAPI struct {
	ctrl     *gomock.Controller
	recorder *MocktransactionAPIMockRecorder
}

// MocktransactionAPIMockRecorder is the mock recorder for MocktransactionAPI
type MocktransactionAPIMockRecorder struct {
	mock *MocktransactionAPI
}

// NewMocktransactionAPI creates a new mock instance
func NewMocktransactionAPI(ctrl *gomock.Controller) *MocktransactionAPI {
	mock := &MocktransactionAPI{ctrl: ctrl}
	mock.recorder = &MocktransactionAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocktransactionAPI) EXPECT() *MocktransactionAPIMockRecorder {
	return m.recorder
}

// CompleteTransaction mocks base method
func (m *MocktransactionAPI) CompleteTransaction(id common0.QueuedTxID, password string) (common0.CompleteTransactionResult, error) {
	ret := m.ctrl.Call(m, "CompleteTransaction", id, password)
	ret0, _ := ret[0].(common0.CompleteTransactionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CompleteTransaction indicates an expected call of CompleteTransaction
func (mr *MocktransactionAPIMockRecorder) CompleteTransaction(id, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompleteTransaction", reflect.TypeOf((*MocktransactionAPI)(nil).CompleteTransaction), id, password)
}

// CompleteTransactions mocks base method
func (m *MocktransactionAPI) CompleteTransactions(ids []common0.QueuedTxID, password string) (common0.CompleteTransactionsResult, map[common0.QueuedTxID]error) {
	ret := m.ctrl.Call(m, "CompleteTransactions", ids, password)
	ret0, _ := ret[0].(common0.CompleteTransactionsResult)
	ret1, _ := ret[1].(map[common0.QueuedTxID]error)
	return ret0, ret1
}

// CompleteTransactions indicates an expected call of CompleteTransactions
func (mr *MocktransactionAPIMockRecorder) CompleteTransactions(ids, password interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompleteTransactions", reflect.TypeOf((*MocktransactionAPI)(nil).CompleteTransactions), ids, password)
}

// DiscardTransaction mocks base method
func (m *MocktransactionAPI) DiscardTransaction(id common0.QueuedTxID) (common0.DiscardTransactionResult, error) {
	ret := m.ctrl.Call(m, "DiscardTransaction", id)
	ret0, _ := ret[0].(common0.DiscardTransactionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DiscardTransaction indicates an expected call of DiscardTransaction
func (mr *MocktransactionAPIMockRecorder) DiscardTransaction(id interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DiscardTransaction", reflect.TypeOf((*MocktransactionAPI)(nil).DiscardTransaction), id)
}

// DiscardTransactions mocks base method
func (m *MocktransactionAPI) DiscardTransactions(ids []common0.QueuedTxID) (common0.DiscardTransactionsResult, map[common0.QueuedTxID]error) {
	ret := m.ctrl.Call(m, "DiscardTransactions", ids)
	ret0, _ := ret[0].(common0.DiscardTransactionsResult)
	ret1, _ := ret[1].(map[common0.QueuedTxID]error)
	return ret0, ret1
}

// DiscardTransactions indicates an expected call of DiscardTransactions
func (mr *MocktransactionAPIMockRecorder) DiscardTransactions(ids interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DiscardTransactions", reflect.TypeOf((*MocktransactionAPI)(nil).DiscardTransactions), ids)
}

// TxQueueManager mocks base method
func (m *MocktransactionAPI) TxQueueManager() common0.TxQueueManager {
	ret := m.ctrl.Call(m, "TxQueueManager")
	ret0, _ := ret[0].(common0.TxQueueManager)
	return ret0
}

// TxQueueManager indicates an expected call of TxQueueManager
func (mr *MocktransactionAPIMockRecorder) TxQueueManager() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TxQueueManager", reflect.TypeOf((*MocktransactionAPI)(nil).TxQueueManager))
}

// SendTransaction mocks base method
func (m *MocktransactionAPI) SendTransaction(ctx context.Context, args common0.SendTxArgs) (common.Hash, error) {
	ret := m.ctrl.Call(m, "SendTransaction", ctx, args)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendTransaction indicates an expected call of SendTransaction
func (mr *MocktransactionAPIMockRecorder) SendTransaction(ctx, args interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendTransaction", reflect.TypeOf((*MocktransactionAPI)(nil).SendTransaction), ctx, args)
}

// MocknodeAPI is a mock of nodeAPI interface
type MocknodeAPI struct {
	ctrl     *gomock.Controller
	recorder *MocknodeAPIMockRecorder
}

// MocknodeAPIMockRecorder is the mock recorder for MocknodeAPI
type MocknodeAPIMockRecorder struct {
	mock *MocknodeAPI
}

// NewMocknodeAPI creates a new mock instance
func NewMocknodeAPI(ctrl *gomock.Controller) *MocknodeAPI {
	mock := &MocknodeAPI{ctrl: ctrl}
	mock.recorder = &MocknodeAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocknodeAPI) EXPECT() *MocknodeAPIMockRecorder {
	return m.recorder
}

// NodeManager mocks base method
func (m *MocknodeAPI) NodeManager() common0.NodeManager {
	ret := m.ctrl.Call(m, "NodeManager")
	ret0, _ := ret[0].(common0.NodeManager)
	return ret0
}

// NodeManager indicates an expected call of NodeManager
func (mr *MocknodeAPIMockRecorder) NodeManager() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NodeManager", reflect.TypeOf((*MocknodeAPI)(nil).NodeManager))
}

// ValidateJSONConfig mocks base method
func (m *MocknodeAPI) ValidateJSONConfig(configJSON string) common0.APIDetailedResponse {
	ret := m.ctrl.Call(m, "ValidateJSONConfig", configJSON)
	ret0, _ := ret[0].(common0.APIDetailedResponse)
	return ret0
}

// ValidateJSONConfig indicates an expected call of ValidateJSONConfig
func (mr *MocknodeAPIMockRecorder) ValidateJSONConfig(configJSON interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateJSONConfig", reflect.TypeOf((*MocknodeAPI)(nil).ValidateJSONConfig), configJSON)
}

// StartNodeAsync mocks base method
func (m *MocknodeAPI) StartNodeAsync(config *params.NodeConfig) (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "StartNodeAsync", config)
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartNodeAsync indicates an expected call of StartNodeAsync
func (mr *MocknodeAPIMockRecorder) StartNodeAsync(config interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartNodeAsync", reflect.TypeOf((*MocknodeAPI)(nil).StartNodeAsync), config)
}

// StopNodeAsync mocks base method
func (m *MocknodeAPI) StopNodeAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "StopNodeAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StopNodeAsync indicates an expected call of StopNodeAsync
func (mr *MocknodeAPIMockRecorder) StopNodeAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopNodeAsync", reflect.TypeOf((*MocknodeAPI)(nil).StopNodeAsync))
}

// RestartNodeAsync mocks base method
func (m *MocknodeAPI) RestartNodeAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "RestartNodeAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RestartNodeAsync indicates an expected call of RestartNodeAsync
func (mr *MocknodeAPIMockRecorder) RestartNodeAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestartNodeAsync", reflect.TypeOf((*MocknodeAPI)(nil).RestartNodeAsync))
}

// ResetChainDataAsync mocks base method
func (m *MocknodeAPI) ResetChainDataAsync() (<-chan struct{}, error) {
	ret := m.ctrl.Call(m, "ResetChainDataAsync")
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResetChainDataAsync indicates an expected call of ResetChainDataAsync
func (mr *MocknodeAPIMockRecorder) ResetChainDataAsync() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResetChainDataAsync", reflect.TypeOf((*MocknodeAPI)(nil).ResetChainDataAsync))
}

// CallRPC mocks base method
func (m *MocknodeAPI) CallRPC(inputJSON string) string {
	ret := m.ctrl.Call(m, "CallRPC", inputJSON)
	ret0, _ := ret[0].(string)
	return ret0
}

// CallRPC indicates an expected call of CallRPC
func (mr *MocknodeAPIMockRecorder) CallRPC(inputJSON interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallRPC", reflect.TypeOf((*MocknodeAPI)(nil).CallRPC), inputJSON)
}

// MocknotificationAPI is a mock of notificationAPI interface
type MocknotificationAPI struct {
	ctrl     *gomock.Controller
	recorder *MocknotificationAPIMockRecorder
}

// MocknotificationAPIMockRecorder is the mock recorder for MocknotificationAPI
type MocknotificationAPIMockRecorder struct {
	mock *MocknotificationAPI
}

// NewMocknotificationAPI creates a new mock instance
func NewMocknotificationAPI(ctrl *gomock.Controller) *MocknotificationAPI {
	mock := &MocknotificationAPI{ctrl: ctrl}
	mock.recorder = &MocknotificationAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocknotificationAPI) EXPECT() *MocknotificationAPIMockRecorder {
	return m.recorder
}

// Notify mocks base method
func (m *MocknotificationAPI) Notify(token string) string {
	ret := m.ctrl.Call(m, "Notify", token)
	ret0, _ := ret[0].(string)
	return ret0
}

// Notify indicates an expected call of Notify
func (mr *MocknotificationAPIMockRecorder) Notify(token interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Notify", reflect.TypeOf((*MocknotificationAPI)(nil).Notify), token)
}

// NotifyUsers mocks base method
func (m *MocknotificationAPI) NotifyUsers(message string, payload go_fcm.NotificationPayload, tokens ...string) error {
	varargs := []interface{}{message, payload}
	for _, a := range tokens {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "NotifyUsers", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// NotifyUsers indicates an expected call of NotifyUsers
func (mr *MocknotificationAPIMockRecorder) NotifyUsers(message, payload interface{}, tokens ...interface{}) *gomock.Call {
	varargs := append([]interface{}{message, payload}, tokens...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NotifyUsers", reflect.TypeOf((*MocknotificationAPI)(nil).NotifyUsers), varargs...)
}

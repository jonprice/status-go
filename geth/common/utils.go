package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/status-im/status-go/geth/common/cipher"
	"github.com/status-im/status-go/geth/log"
	"github.com/status-im/status-go/static"
)

const (
	// MessageIDKey is a key for message ID
	// This ID is required to track from which chat a given send transaction request is coming.
	MessageIDKey = contextKey("message_id")

	// KeysPath path to encrypted keys
	KeysPath = "./static/keys"

	keyEnv   = "STATUS_KEY"
	nonceEnv = "STATUS_NONCE"
)

type contextKey string // in order to make sure that our context key does not collide with keys from other packages

// errors
var (
	ErrInvalidAccountAddressOrKey = errors.New("cannot parse address or key to valid account address")
)

// ParseAccountString parses hex encoded string and returns is as accounts.Account.
func ParseAccountString(account string) (accounts.Account, error) {
	// valid address, convert to account
	if common.IsHexAddress(account) {
		return accounts.Account{Address: common.HexToAddress(account)}, nil
	}

	return accounts.Account{}, ErrInvalidAccountAddressOrKey
}

// FromAddress converts account address from string to common.Address.
// The function is useful to format "From" field of send transaction struct.
func FromAddress(accountAddress string) common.Address {
	from, err := ParseAccountString(accountAddress)
	if err != nil {
		return common.Address{}
	}

	return from.Address
}

// ToAddress converts account address from string to *common.Address.
// The function is useful to format "To" field of send transaction struct.
func ToAddress(accountAddress string) *common.Address {
	to, err := ParseAccountString(accountAddress)
	if err != nil {
		return nil
	}

	return &to.Address
}

// RestoreFile checks if decrypted file exists in dir, and if not
// tries to restore and decrypt it (from static resources, see "static/keys" folder).
func RestoreFile(dir, file string) error {
	text, err := ReadEncryptedFile(dir, file)
	if err != nil {
		return err
	}
	if len(text) == 0 {
		return nil
	}

	dst := filepath.Join(dir, file)
	err = ioutil.WriteFile(dst, text, 0644)
	if err != nil {
		log.Warn("cannot restore file", "error", err)
		return err
	}

	return nil
}

// ReadEncryptedFile restores and reads encrypted text.
func ReadEncryptedFile(dir, file string) ([]byte, error) {
	dst := filepath.Join(dir, file)
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		return nil, nil
	}

	key := os.Getenv(keyEnv)
	nonce := os.Getenv(nonceEnv)
	if len(key) == 0 || len(nonce) == 0 {
		err := errors.New("cant get key and nonce to decrypt file " + dst)
		log.Warn("ReadEncryptedFile", "error", err)
		return nil, err
	}

	cipherText := static.MustAsset(filepath.Join("keys", file) + cipher.CipherExt)
	text, err := cipher.Decrypt(key, nonce, cipherText)
	if err != nil {
		log.Warn("cannot restore file", "error", err)
		return nil, err
	}

	return text, nil
}

// PanicAfter throws panic() after waitSeconds, unless abort channel receives notification
func PanicAfter(waitSeconds time.Duration, abort chan struct{}, desc string) {
	go func() {
		select {
		case <-abort:
			return
		case <-time.After(waitSeconds):
			panic("whatever you were doing takes toooo long: " + desc)
		}
	}()
}

// NameOf returns name of caller, at runtime
func NameOf(f interface{}) string {
	v := reflect.ValueOf(f)
	if v.Kind() == reflect.Func {
		if rf := runtime.FuncForPC(v.Pointer()); rf != nil {
			return rf.Name()
		}
	}
	return v.String()
}

// MessageIDFromContext returns message id from context (if exists)
func MessageIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if messageID, ok := ctx.Value(MessageIDKey).(string); ok {
		return messageID
	}

	return ""
}

// ParseJSONArray parses JSON array into Go array of string
func ParseJSONArray(items string) ([]string, error) {
	var parsedItems []string
	err := json.Unmarshal([]byte(items), &parsedItems)
	if err != nil {
		return nil, err
	}

	return parsedItems, nil
}

// Fatalf is used to halt the execution.
// When called the function prints stack end exits.
// Failure is logged into both StdErr and StdOut.
func Fatalf(reason interface{}, args ...interface{}) {
	// decide on output stream
	w := io.MultiWriter(os.Stdout, os.Stderr)
	outf, _ := os.Stdout.Stat()
	errf, _ := os.Stderr.Stat()
	if outf != nil && errf != nil && os.SameFile(outf, errf) {
		w = os.Stderr
	}

	// find out whether error or string has been passed as a reason
	r := reflect.ValueOf(reason)
	if r.Kind() == reflect.String {
		fmt.Fprintf(w, "Fatal Failure: "+reason.(string)+"\n", args)
	} else {
		fmt.Fprintf(w, "Fatal Failure: %v\n", reason.(error))
	}

	debug.PrintStack()

	os.Exit(1)
}

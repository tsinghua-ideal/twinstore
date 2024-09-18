package lotusdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	dwal "dwal"
	"encoding/binary"
	"encoding/hex"
	"io"
)

// LogRecordType is the type of the log record.
type LogRecordType = byte

const (
	// LogRecordNormal is the normal log record type.
	LogRecordNormal LogRecordType = iota
	// LogRecordDeleted is the deleted log record type.
	LogRecordDeleted
	// LogRecordBatchFinished is the batch finished log record type.
	LogRecordBatchFinished
)

// type batchId keySize valueSize
//
//	1  +  10  +   5   +   5 = 21
const maxLogRecordHeaderSize = binary.MaxVarintLen32*2 + binary.MaxVarintLen64 + 1

// LogRecord is the log record of the key/value pair.
// It contains the key, the value, the record type and the batch id
// It will be encoded to byte slice and written to the wal.
type LogRecord struct {
	Key     []byte
	Value   []byte
	Type    LogRecordType
	BatchID uint64
}

// +-------------+-------------+-------------+--------------+-------------+--------------+
// |    type     |  batch id   |   key size  |   value size |      key    |      value   |
// +-------------+-------------+-------------+--------------+-------------+--------------+
//
//	1 byte	      varint(max 10) varint(max 5)  varint(max 5)     varint		varint
func encodeLogRecord(logRecord *LogRecord) []byte {
	header := make([]byte, maxLogRecordHeaderSize)

	header[0] = logRecord.Type
	var index = 1

	// batch id
	index += binary.PutUvarint(header[index:], logRecord.BatchID)
	// key size
	index += binary.PutVarint(header[index:], int64(len(logRecord.Key)))
	// value size
	index += binary.PutVarint(header[index:], int64(len(logRecord.Value)))

	var size = index + len(logRecord.Key) + len(logRecord.Value)
	encBytes := make([]byte, size)

	// copy header
	copy(encBytes[:index], header[:index])
	// copy key
	copy(encBytes[index:], logRecord.Key)
	// copy value
	copy(encBytes[index+len(logRecord.Key):], logRecord.Value)

	return encBytes
}

// decodeLogRecord decodes the log record from the given byte slice.
func decodeLogRecord(buf []byte) *LogRecord {
	recordType := buf[0]

	var index uint32 = 1
	// batch id
	batchID, n := binary.Uvarint(buf[index:])
	index += uint32(n)

	// key size
	keySize, n := binary.Varint(buf[index:])
	index += uint32(n)

	// value size
	valueSize, n := binary.Varint(buf[index:])
	index += uint32(n)

	// copy key
	key := make([]byte, keySize)
	copy(key, buf[index:index+uint32(keySize)])
	index += uint32(keySize)

	// copy value
	value := make([]byte, valueSize)
	copy(value, buf[index:index+uint32(valueSize)])

	return &LogRecord{Key: key, Value: value,
		BatchID: batchID, Type: recordType}
}

// KeyPosition is the position of the key in the value log.
type KeyPosition struct {
	key       []byte
	partition uint32
	position  *dwal.ChunkPosition
}

// ValueLogRecord is the record of the key/value pair in the value log.
type ValueLogRecord struct {
	key   []byte
	value []byte
}

func encodeValueLogRecord(record *ValueLogRecord) ([]byte, []byte) {
	buf := make([]byte, 4+len(record.key)+len(record.value))
	keySize := 4
	index := 0
	binary.LittleEndian.PutUint32(buf[index:keySize], uint32(len(record.key)))
	index += keySize

	copy(buf[index:index+len(record.key)], record.key)
	index += len(record.key)
	copy(buf[index:], record.value)

	aes_key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	block, err := aes.NewCipher(aes_key)
	if err != nil {
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	buf_enc := aesgcm.Seal(nil, nonce, buf, nil)
	return buf_enc, nonce
}

func decodeValueLogRecord(buf_enc []byte, nonce []byte) *ValueLogRecord {
	aes_key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	block, err := aes.NewCipher(aes_key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	buf, err := aesgcm.Open(nil, nonce, buf_enc, nil)
	if err != nil {
		panic(err.Error())
	}

	var keySize uint32 = 4
	keyLen := binary.LittleEndian.Uint32(buf[:keySize])
	key := make([]byte, keyLen)
	copy(key, buf[keySize:keySize+keyLen])
	value := make([]byte, uint32(len(buf))-keyLen-keySize)
	copy(value, buf[keySize+keyLen:])
	return &ValueLogRecord{key: key, value: value}
}

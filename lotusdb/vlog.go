package lotusdb

import (
	"context"
	"fmt"

	dwal "dwal"

	"golang.org/x/sync/errgroup"
)

const (
	valueLogFileExt     = ".VLOG.%d"
	tempValueLogFileExt = ".VLOG.%d.temp"
)

// valueLog value log is named after the concept in Wisckey paper
// https://www.usenix.org/system/files/conference/fast16/fast16-papers-lu.pdf
type valueLog struct {
	walFiles []*dwal.WAL
	options  valueLogOptions
}

type valueLogOptions struct {
	// dirPath specifies the directory path where the WAL segment files will be stored.
	dirPath string

	// nonceDirPath specifies the directory path where the WAL nonce segment files will be stored.
	nonceDirPath string

	// segmentSize specifies the maximum size of each segment file in bytes.
	segmentSize int64

	// value log are partitioned to several parts for concurrent writing and reading
	partitionNum uint32

	// hash function for sharding
	hashKeyFunction func([]byte) uint64

	// writing validEntries to disk after reading the specified number of entries.
	compactBatchCount int
}

// open wal files for value log, it will open several wal files for concurrent writing and reading
// the number of wal files is specified by the partitionNum.
func openValueLog(options valueLogOptions) (*valueLog, error) {
	var walFiles []*dwal.WAL

	for i := 0; i < int(options.partitionNum); i++ {
		vLogWal, err := dwal.Open(dwal.Options{
			DirPath:        options.dirPath,
			NonceDirPath:   options.nonceDirPath,
			SegmentSize:    options.segmentSize,
			SegmentFileExt: fmt.Sprintf(valueLogFileExt, i),
			Sync:           false, // we will sync manually
			BytesPerSync:   0,     // the same as Sync
		})
		if err != nil {
			return nil, err
		}
		walFiles = append(walFiles, vLogWal)
	}

	return &valueLog{walFiles: walFiles, options: options}, nil
}

// read the value log record from the specified position.
func (vlog *valueLog) read(pos *KeyPosition) (*ValueLogRecord, error) {
	buf, nonce, err := vlog.walFiles[pos.partition].Read(pos.position)
	if err != nil {
		return nil, err
	}
	log := decodeValueLogRecord(buf, nonce)
	return log, nil
}

// write the value log record to the value log, it will be separated to several partitions
// and write to the corresponding partition concurrently.
func (vlog *valueLog) writeBatch(records []*ValueLogRecord) ([]*KeyPosition, error) {
	// group the records by partition
	partitionRecords := make([][]*ValueLogRecord, vlog.options.partitionNum)
	for _, record := range records {
		p := vlog.getKeyPartition(record.key)
		partitionRecords[p] = append(partitionRecords[p], record)
	}

	// channel for receiving the positions of the records after writing to the value log
	posChan := make(chan []*KeyPosition, vlog.options.partitionNum)
	g, ctx := errgroup.WithContext(context.Background())
	for i := 0; i < int(vlog.options.partitionNum); i++ {
		if len(partitionRecords[i]) == 0 {
			continue
		}

		part := i
		g.Go(func() error {
			var err error
			defer func() {
				if err != nil {
					vlog.walFiles[part].ClearPendingWrites()
				}
			}()

			var keyPositions []*KeyPosition
			writeIdx := 0
			for _, record := range partitionRecords[part] {
				select {
				case <-ctx.Done():
					err = ctx.Err()
					return err
				default:
					enc_buf, nonce := encodeValueLogRecord(record)
					vlog.walFiles[part].PendingWrites(enc_buf, nonce)
				}
			}
			positions, err := vlog.walFiles[part].WriteAll()
			if err != nil {
				return err
			}
			for i, pos := range positions {
				keyPositions = append(keyPositions, &KeyPosition{
					key:       partitionRecords[part][writeIdx+i].key,
					partition: uint32(part),
					position:  pos,
				})
			}
			posChan <- keyPositions
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	close(posChan)

	// nwo we get the positions of the records, we can return them to the caller
	var keyPositions []*KeyPosition
	for i := 0; i < int(vlog.options.partitionNum); i++ {
		pos := <-posChan
		keyPositions = append(keyPositions, pos...)
	}

	return keyPositions, nil
}

// sync the value log to disk.
func (vlog *valueLog) sync() error {
	for _, walFile := range vlog.walFiles {
		if err := walFile.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// close the value log.
func (vlog *valueLog) close() error {
	for _, walFile := range vlog.walFiles {
		if err := walFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (vlog *valueLog) getKeyPartition(key []byte) int {
	return int(vlog.options.hashKeyFunction(key) % uint64(vlog.options.partitionNum))
}

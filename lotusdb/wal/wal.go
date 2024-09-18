package wal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	initialSegmentFileID = 1
)

var (
	ErrValueTooLarge       = errors.New("the data size can't larger than segment size")
	ErrPendingSizeTooLarge = errors.New("the upper bound of pendingWrites can't larger than segment size")
)

// WAL represents a Write-Ahead Log structure that provides durability
// and fault-tolerance for incoming writes.
// It consists of an activeSegment, which is the current segment file
// used for new incoming writes, and olderSegments,
// which is a map of segment files used for read operations.
//
// The options field stores various configuration options for the WAL.
//
// The mu sync.RWMutex is used for concurrent access to the WAL data structure,
// ensuring safe access and modification.
type WAL struct {
	activeSegment      *segment               // active segment file, used for new incoming writes.
	olderSegments      map[SegmentID]*segment // older segment files, only used for read.
	options            Options
	mu                 sync.RWMutex
	bytesWrite         uint32
	renameIds          []SegmentID
	pendingWrites      [][]byte
	pendingNonceWrites [][]byte
	pendingSize        int64
	pendingWritesLock  sync.Mutex
	nonceFile          *nonceFile
}

// Reader represents a reader for the WAL.
// It consists of segmentReaders, which is a slice of segmentReader
// structures sorted by segment id,
// and currentReader, which is the index of the current segmentReader in the slice.
//
// The currentReader field is used to iterate over the segmentReaders slice.
type Reader struct {
	segmentReaders []*segmentReader
	nonceReader    *nonceFile
	currentReader  int
	valueNum       int64
}

// Open opens a WAL with the given options.
// It will create the directory if not exists, and open all segment files in the directory.
// If there is no segment file in the directory, it will create a new one.
func Open(options Options) (*WAL, error) {
	if !strings.HasPrefix(options.SegmentFileExt, ".") {
		return nil, fmt.Errorf("segment file extension must start with '.'")
	}
	wal := &WAL{
		options:            options,
		olderSegments:      make(map[SegmentID]*segment),
		pendingWrites:      make([][]byte, 0),
		pendingNonceWrites: make([][]byte, 0),
	}

	// create the directory if not exists.
	if err := os.MkdirAll(options.DirPath, os.ModePerm); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(options.NonceDirPath, os.ModePerm); err != nil {
		return nil, err
	}

	// iterate the dir and open all segment files.
	entries, err := os.ReadDir(options.DirPath)
	if err != nil {
		return nil, err
	}

	// get all segment file ids.
	var segmentIDs []int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var id int
		_, err := fmt.Sscanf(entry.Name(), "%d"+options.SegmentFileExt, &id)
		if err != nil {
			continue
		}
		segmentIDs = append(segmentIDs, id)
	}

	nonceFile, err := openNonceFile(options.NonceDirPath, options.SegmentFileExt)
	if err != nil {
		return nil, err
	}
	wal.nonceFile = nonceFile

	// empty directory, just initialize a new segment file.
	if len(segmentIDs) == 0 {
		segment, err := openSegmentFile(options.DirPath, options.SegmentFileExt,
			initialSegmentFileID)
		if err != nil {
			return nil, err
		}
		wal.activeSegment = segment
	} else {
		// open the segment files in order, get the max one as the active segment file.
		sort.Ints(segmentIDs)

		for i, segId := range segmentIDs {
			segment, err := openSegmentFile(options.DirPath, options.SegmentFileExt,
				uint32(segId))
			if err != nil {
				return nil, err
			}
			if i == len(segmentIDs)-1 {
				wal.activeSegment = segment
			} else {
				wal.olderSegments[segment.id] = segment
			}
		}
	}

	return wal, nil
}

// SegmentFileName returns the file name of a segment file.
func SegmentFileName(dirPath string, extName string, id SegmentID) string {
	return filepath.Join(dirPath, fmt.Sprintf("%09d"+extName, id))
}

func NonceFileName(dirPath string, extName string) string {
	return filepath.Join(dirPath, fmt.Sprintf("nonce"+extName))
}

// OpenNewActiveSegment opens a new segment file
// and sets it as the active segment file.
// It is used when even the active segment file is not full,
// but the user wants to create a new segment file.
//
// It is now used by Merge operation of rosedb, not a common usage for most users.
func (wal *WAL) OpenNewActiveSegment() error {
	wal.mu.Lock()
	defer wal.mu.Unlock()
	// sync the active segment file.
	if err := wal.activeSegment.Sync(); err != nil {
		return err
	}
	if err := wal.nonceFile.Sync(); err != nil {
		return err
	}
	// create a new segment file and set it as the active one.
	segment, err := openSegmentFile(wal.options.DirPath, wal.options.SegmentFileExt,
		wal.activeSegment.id+1)
	if err != nil {
		return err
	}
	wal.olderSegments[wal.activeSegment.id] = wal.activeSegment
	wal.activeSegment = segment
	return nil
}

// ActiveSegmentID returns the id of the active segment file.
func (wal *WAL) ActiveSegmentID() SegmentID {
	wal.mu.RLock()
	defer wal.mu.RUnlock()

	return wal.activeSegment.id
}

// IsEmpty returns whether the WAL is empty.
// Only there is only one empty active segment file, which means the WAL is empty.
func (wal *WAL) IsEmpty() bool {
	wal.mu.RLock()
	defer wal.mu.RUnlock()

	return len(wal.olderSegments) == 0 && wal.activeSegment.Size() == 0
}

// SetIsStartupTraversal This is only used if the WAL is during startup traversal.
// Such as rosedb/lotusdb startup, so it's not a common usage for most users.
// And notice that if you set it to true, only one reader can read the data from the WAL
// (Single Thread).
func (wal *WAL) SetIsStartupTraversal(v bool) {
	for _, seg := range wal.olderSegments {
		seg.isStartupTraversal = v
	}
	wal.activeSegment.isStartupTraversal = v
}

// NewReaderWithMax returns a new reader for the WAL,
// and the reader will only read the data from the segment file
// whose id is less than or equal to the given segId.
//
// It is now used by the Merge operation of rosedb, not a common usage for most users.
func (wal *WAL) NewReaderWithMax(segId SegmentID) *Reader {
	wal.mu.RLock()
	defer wal.mu.RUnlock()

	// get all segment readers.
	var segmentReaders []*segmentReader
	for _, segment := range wal.olderSegments {
		if segId == 0 || segment.id <= segId {
			reader := segment.NewReader()
			segmentReaders = append(segmentReaders, reader)
		}
	}
	if segId == 0 || wal.activeSegment.id <= segId {
		reader := wal.activeSegment.NewReader()
		segmentReaders = append(segmentReaders, reader)
	}

	// sort the segment readers by segment id.
	sort.Slice(segmentReaders, func(i, j int) bool {
		return segmentReaders[i].segment.id < segmentReaders[j].segment.id
	})

	return &Reader{
		segmentReaders: segmentReaders,
		nonceReader:    wal.nonceFile,
		currentReader:  0,
		valueNum:       0,
	}
}

// NewReaderWithStart returns a new reader for the WAL,
// and the reader will only read the data from the segment file
// whose position is greater than or equal to the given position.
func (wal *WAL) NewReaderWithStart(startPos *ChunkPosition) (*Reader, error) {
	if startPos == nil {
		return nil, errors.New("start position is nil")
	}
	wal.mu.RLock()
	defer wal.mu.RUnlock()

	reader := wal.NewReader()
	for {
		// skip the segment readers whose id is less than the given position's segment id.
		if reader.CurrentSegmentId() < startPos.SegmentId {
			reader.SkipCurrentSegment()
			continue
		}
		// skip the chunk whose position is less than the given position.
		currentPos := reader.CurrentChunkPosition()
		if currentPos.BlockNumber >= startPos.BlockNumber &&
			currentPos.ChunkOffset >= startPos.ChunkOffset {
			break
		}
		// call Next to find again.
		if _, _, _, err := reader.Next(); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return reader, nil
}

// NewReader returns a new reader for the WAL.
// It will iterate all segment files and read all data from them.
func (wal *WAL) NewReader() *Reader {
	return wal.NewReaderWithMax(0)
}

// Next returns the next chunk data and its position in the WAL.
// If there is no data, io.EOF will be returned.
//
// The position can be used to read the data from the segment file.
func (r *Reader) Next() ([]byte, []byte, *ChunkPosition, error) {
	if r.currentReader >= len(r.segmentReaders) {
		return nil, nil, nil, io.EOF
	}

	data, position, err := r.segmentReaders[r.currentReader].Next()
	if err == io.EOF {
		r.currentReader++
		return r.Next()
	}
	position.ValueNum = r.valueNum
	nonce := make([]byte, nonceSize)
	n, err := r.nonceReader.fd.ReadAt(nonce, position.ValueNum*nonceSize)
	if n != nonceSize || err != nil {
		return nil, nil, nil, io.EOF
	}
	r.valueNum += 1
	return data, nonce, position, err
}

// SkipCurrentSegment skips the current segment file
// when reading the WAL.
//
// It is now used by the Merge operation of rosedb, not a common usage for most users.
func (r *Reader) SkipCurrentSegment() {
	r.currentReader++
}

// CurrentSegmentId returns the id of the current segment file
// when reading the WAL.
func (r *Reader) CurrentSegmentId() SegmentID {
	return r.segmentReaders[r.currentReader].segment.id
}

// CurrentChunkPosition returns the position of the current chunk data
func (r *Reader) CurrentChunkPosition() *ChunkPosition {
	reader := r.segmentReaders[r.currentReader]
	return &ChunkPosition{
		SegmentId:   reader.segment.id,
		BlockNumber: reader.blockNumber,
		ChunkOffset: reader.chunkOffset,
	}
}

// ClearPendingWrites clear pendingWrite and reset pendingSize
func (wal *WAL) ClearPendingWrites() {
	wal.pendingWritesLock.Lock()
	defer wal.pendingWritesLock.Unlock()

	wal.pendingSize = 0
	wal.pendingWrites = wal.pendingWrites[:0]
	wal.pendingNonceWrites = wal.pendingNonceWrites[:0]
}

// PendingWrites add data to wal.pendingWrites and wait for batch write.
// If the data in pendingWrites exceeds the size of one segment,
// it will return a 'ErrPendingSizeTooLarge' error and clear the pendingWrites.
func (wal *WAL) PendingWrites(data []byte, nonce []byte) {
	wal.pendingWritesLock.Lock()
	defer wal.pendingWritesLock.Unlock()

	size := wal.maxDataWriteSize(int64(len(data)))
	wal.pendingSize += size
	wal.pendingWrites = append(wal.pendingWrites, data)
	wal.pendingNonceWrites = append(wal.pendingNonceWrites, nonce)
}

// rotateActiveSegment create a new segment file and replace the activeSegment.
func (wal *WAL) rotateActiveSegment() error {
	if err := wal.activeSegment.Sync(); err != nil {
		return err
	}
	if err := wal.nonceFile.Sync(); err != nil {
		return err
	}
	wal.bytesWrite = 0
	segment, err := openSegmentFile(wal.options.DirPath, wal.options.SegmentFileExt,
		wal.activeSegment.id+1)
	if err != nil {
		return err
	}
	wal.olderSegments[wal.activeSegment.id] = wal.activeSegment
	wal.activeSegment = segment
	return nil
}

// WriteAll write wal.pendingWrites to WAL and then clear pendingWrites,
// it will not sync the segment file based on wal.options, you should call Sync() manually.
func (wal *WAL) WriteAll() ([]*ChunkPosition, error) {
	if len(wal.pendingWrites) == 0 {
		return make([]*ChunkPosition, 0), nil
	}

	wal.mu.Lock()
	defer func() {
		wal.ClearPendingWrites()
		wal.mu.Unlock()
	}()

	// if the pending size is still larger than segment size, return error
	if wal.pendingSize > wal.options.SegmentSize {
		return nil, ErrPendingSizeTooLarge
	}

	// if the active segment file is full, sync it and create a new one.
	if wal.activeSegment.Size()+wal.pendingSize > wal.options.SegmentSize {
		if err := wal.rotateActiveSegment(); err != nil {
			return nil, err
		}
	}

	// write all data to the active segment file.
	positions, err := wal.activeSegment.writeAll(wal.pendingWrites)
	if err != nil {
		return nil, err
	}

	wal.nonceFile.writeAll(wal.pendingNonceWrites, positions)
	return positions, nil
}

// Write writes the data to the WAL.
// Actually, it writes the data to the active segment file.
// It returns the position of the data in the WAL, and an error if any.
func (wal *WAL) Write(data []byte, nonce []byte) (*ChunkPosition, error) {
	wal.mu.Lock()
	defer wal.mu.Unlock()
	if int64(len(data))+chunkHeaderSize > wal.options.SegmentSize {
		return nil, ErrValueTooLarge
	}
	// if the active segment file is full, sync it and create a new one.
	if wal.isFull(int64(len(data))) {
		if err := wal.rotateActiveSegment(); err != nil {
			return nil, err
		}
	}

	// write the data to the active segment file.
	position, err := wal.activeSegment.Write(data)
	if err != nil {
		return nil, err
	}
	err = wal.nonceFile.Write(nonce, position)
	if err != nil {
		return nil, err
	}

	// update the bytesWrite field.
	wal.bytesWrite += position.ChunkSize

	// sync the active segment file if needed.
	var needSync = wal.options.Sync
	if !needSync && wal.options.BytesPerSync > 0 {
		needSync = wal.bytesWrite >= wal.options.BytesPerSync
	}
	if needSync {
		if err := wal.activeSegment.Sync(); err != nil {
			return nil, err
		}
		if err := wal.nonceFile.Sync(); err != nil {
			return nil, err
		}
		wal.bytesWrite = 0
	}

	return position, nil
}

// Read reads the data from the WAL according to the given position.
func (wal *WAL) Read(pos *ChunkPosition) ([]byte, []byte, error) {
	wal.mu.RLock()
	defer wal.mu.RUnlock()

	// find the segment file according to the position.
	var segment *segment
	if pos.SegmentId == wal.activeSegment.id {
		segment = wal.activeSegment
	} else {
		segment = wal.olderSegments[pos.SegmentId]
	}

	if segment == nil {
		return nil, nil, fmt.Errorf("segment file %d%s not found", pos.SegmentId, wal.options.SegmentFileExt)
	}

	nonce := make([]byte, nonceSize)
	n, err := wal.nonceFile.fd.ReadAt(nonce, pos.ValueNum*nonceSize)
	if err != nil {
		return nil, nil, err
	} else if n != nonceSize {
		return nil, nil, fmt.Errorf("nonce is incomplete")
	}
	var data []byte
	data, err = segment.Read(pos.BlockNumber, pos.ChunkOffset)

	// read the data from the segment file.
	return data, nonce, err
}

// Close closes the WAL.
func (wal *WAL) Close() error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	// close all segment files.
	for _, segment := range wal.olderSegments {
		if err := segment.Close(); err != nil {
			return err
		}
		wal.renameIds = append(wal.renameIds, segment.id)
	}
	wal.olderSegments = nil

	wal.renameIds = append(wal.renameIds, wal.activeSegment.id)
	// close the active segment file.
	if err := wal.activeSegment.Close(); err != nil {
		return err
	}
	return wal.nonceFile.Close()
}

// Delete deletes all segment files of the WAL.
func (wal *WAL) Delete() error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	// delete all segment files.
	for _, segment := range wal.olderSegments {
		if err := segment.Remove(); err != nil {
			return err
		}
	}
	wal.olderSegments = nil

	// delete the active segment file.
	if err := wal.activeSegment.Remove(); err != nil {
		return err
	}
	return wal.nonceFile.Remove()
}

// Sync syncs the active segment file to stable storage like disk.
func (wal *WAL) Sync() error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	return wal.activeSegment.Sync()
}

// RenameFileExt renames all segment files' extension name.
// It is now used by the Merge operation of loutsdb, not a common usage for most users.
func (wal *WAL) RenameFileExt(ext string) error {
	if !strings.HasPrefix(ext, ".") {
		return fmt.Errorf("segment file extension must start with '.'")
	}
	wal.mu.Lock()
	defer wal.mu.Unlock()

	renameFile := func(id SegmentID) error {
		oldName := SegmentFileName(wal.options.DirPath, wal.options.SegmentFileExt, id)
		newName := SegmentFileName(wal.options.DirPath, ext, id)
		return os.Rename(oldName, newName)
	}

	renameNonceFile := func() error {
		oldName := NonceFileName(wal.options.NonceDirPath, wal.options.SegmentFileExt)
		newName := NonceFileName(wal.options.NonceDirPath, ext)
		return os.Rename(oldName, newName)
	}

	for _, id := range wal.renameIds {
		if err := renameFile(id); err != nil {
			return err
		}
	}

	if err := renameNonceFile(); err != nil {
		return err
	}

	wal.options.SegmentFileExt = ext
	return nil
}

func (wal *WAL) isFull(delta int64) bool {
	return wal.activeSegment.Size()+wal.maxDataWriteSize(delta) > wal.options.SegmentSize
}

// maxDataWriteSize calculate the possible maximum size.
// the maximum size = max padding + (num_block + 1) * headerSize + dataSize
func (wal *WAL) maxDataWriteSize(size int64) int64 {
	return chunkHeaderSize + size + (size/blockSize+1)*chunkHeaderSize
}

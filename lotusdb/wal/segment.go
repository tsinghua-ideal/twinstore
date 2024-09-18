package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"

	"github.com/valyala/bytebufferpool"
)

type ChunkType = byte
type SegmentID = uint32

const (
	ChunkTypeFull ChunkType = iota
	ChunkTypeFirst
	ChunkTypeMiddle
	ChunkTypeLast
)

var (
	ErrClosed     = errors.New("the segment file is closed")
	ErrInvalidCRC = errors.New("invalid crc, the data may be corrupted")
)

const (
	// 7 Bytes
	// Checksum Length Type
	//    4      2     1
	chunkHeaderSize = 7

	// 32 KB
	blockSize = 32 * KB

	fileModePerm = 0644

	// uin32 + uint32 + int64 + uin32
	// segmentId + BlockNumber + ChunkOffset + ChunkSize
	maxLen = binary.MaxVarintLen32*3 + binary.MaxVarintLen64

	// 12-byte nonce for AES-256
	nonceSize = 12
)

type nonceFile struct {
	fd     *os.File
	curNum int64
	closed bool
}

// Segment represents a single segment file in WAL.
// The segment file is append-only, and the data is written in blocks.
// Each block is 32KB, and the data is written in chunks.
type segment struct {
	id                 SegmentID
	fd                 *os.File
	currentBlockNumber uint32
	currentBlockSize   uint32
	closed             bool
	header             []byte
	startupBlock       *startupBlock
	isStartupTraversal bool
}

// segmentReader is used to iterate all the data from the segment file.
// You can call Next to get the next chunk data,
// and io.EOF will be returned when there is no data.
type segmentReader struct {
	segment     *segment
	blockNumber uint32
	chunkOffset int64
}

// There is only one reader(single goroutine) for startup traversal,
// so we can use one block to finish the whole traversal
// to avoid memory allocation.
type startupBlock struct {
	block       []byte
	blockNumber int64
}

// ChunkPosition represents the position of a chunk in a segment file.
// Used to read the data from the segment file.
type ChunkPosition struct {
	SegmentId SegmentID
	// BlockNumber The block number of the chunk in the segment file.
	BlockNumber uint32
	// ChunkOffset The start offset of the chunk in the segment file.
	ChunkOffset int64
	// ChunkSize How many bytes the chunk data takes up in the segment file.
	ChunkSize uint32
	// ValueNum What the number of the current value is.
	ValueNum int64
}

var blockPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, blockSize)
	},
}

func getBuffer() []byte {
	return blockPool.Get().([]byte)
}

func putBuffer(buf []byte) {
	blockPool.Put(buf)
}

// openNonceFile a new nonce file.
func openNonceFile(dirPath, extName string) (*nonceFile, error) {
	fd, err := os.OpenFile(
		NonceFileName(dirPath, extName),
		os.O_CREATE|os.O_RDWR|os.O_APPEND,
		fileModePerm,
	)

	if err != nil {
		return nil, err
	}

	// set the current block number and block size.
	offset, err := fd.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek to the end of nonce file %s failed: %v", extName, err)
	}

	return &nonceFile{
		fd:     fd,
		curNum: offset / nonceSize,
	}, nil
}

// Write nonces to file
func (seg *nonceFile) writeAll(nonce [][]byte, positions []*ChunkPosition) error {
	for i := 0; i < len(nonce); i++ {
		// write the nonce into underlying file
		if _, err := seg.fd.Write(nonce[i]); err != nil {
			return err
		}
		positions[i].ValueNum = seg.curNum
		seg.curNum += 1
	}
	return nil
}

// Write nonce to file.
func (seg *nonceFile) Write(nonce []byte, position *ChunkPosition) error {
	if len(nonce) == 0 {
		return nil
	}
	// write the nonce into underlying file
	if _, err := seg.fd.Write(nonce); err != nil {
		return err
	}
	position.ValueNum = seg.curNum
	seg.curNum += 1
	return nil
}

// Sync flushes the segment file to disk.
func (seg *nonceFile) Sync() error {
	if seg.closed {
		return nil
	}
	return seg.fd.Sync()
}

// Remove removes the segment file.
func (seg *nonceFile) Remove() error {
	if !seg.closed {
		seg.closed = true
		if err := seg.fd.Close(); err != nil {
			return err
		}
	}

	return os.Remove(seg.fd.Name())
}

// Close closes the segment file.
func (seg *nonceFile) Close() error {
	if seg.closed {
		return nil
	}

	seg.closed = true
	return seg.fd.Close()
}

// openSegmentFile a new segment file.
func openSegmentFile(dirPath, extName string, id uint32) (*segment, error) {
	fd, err := os.OpenFile(
		SegmentFileName(dirPath, extName, id),
		os.O_CREATE|os.O_RDWR|os.O_APPEND,
		fileModePerm,
	)

	if err != nil {
		return nil, err
	}

	// set the current block number and block size.
	offset, err := fd.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek to the end of segment file %d%s failed: %v", id, extName, err)
	}

	return &segment{
		id:                 id,
		fd:                 fd,
		header:             make([]byte, chunkHeaderSize),
		currentBlockNumber: uint32(offset / blockSize),
		currentBlockSize:   uint32(offset % blockSize),
		startupBlock: &startupBlock{
			block:       make([]byte, blockSize),
			blockNumber: -1,
		},
		isStartupTraversal: false,
	}, nil
}

// NewReader creates a new segment reader.
// You can call Next to get the next chunk data,
// and io.EOF will be returned when there is no data.
func (seg *segment) NewReader() *segmentReader {
	return &segmentReader{
		segment:     seg,
		blockNumber: 0,
		chunkOffset: 0,
	}
}

// Sync flushes the segment file to disk.
func (seg *segment) Sync() error {
	if seg.closed {
		return nil
	}
	return seg.fd.Sync()
}

// Remove removes the segment file.
func (seg *segment) Remove() error {
	if !seg.closed {
		seg.closed = true
		if err := seg.fd.Close(); err != nil {
			return err
		}
	}

	return os.Remove(seg.fd.Name())
}

// Close closes the segment file.
func (seg *segment) Close() error {
	if seg.closed {
		return nil
	}

	seg.closed = true
	return seg.fd.Close()
}

// Size returns the size of the segment file.
func (seg *segment) Size() int64 {
	size := int64(seg.currentBlockNumber) * int64(blockSize)
	return size + int64(seg.currentBlockSize)
}

// writeToBuffer calculate chunkPosition for data, write data to bytebufferpool, update segment status
// The data will be written in chunks, and the chunk has four types:
// ChunkTypeFull, ChunkTypeFirst, ChunkTypeMiddle, ChunkTypeLast.
//
// Each chunk has a header, and the header contains the length, type and checksum.
// And the payload of the chunk is the real data you want to Write.
func (seg *segment) writeToBuffer(data []byte, chunkBuffer *bytebufferpool.ByteBuffer) (*ChunkPosition, error) {
	startBufferLen := chunkBuffer.Len()
	padding := uint32(0)

	if seg.closed {
		return nil, ErrClosed
	}

	// if the left block size can not hold the chunk header, padding the block
	if seg.currentBlockSize+chunkHeaderSize >= blockSize {
		// padding if necessary
		if seg.currentBlockSize < blockSize {
			p := make([]byte, blockSize-seg.currentBlockSize)
			chunkBuffer.B = append(chunkBuffer.B, p...)
			padding += blockSize - seg.currentBlockSize

			// a new block
			seg.currentBlockNumber += 1
			seg.currentBlockSize = 0
		}
	}

	// return the start position of the chunk, then the user can use it to read the data.
	position := &ChunkPosition{
		SegmentId:   seg.id,
		BlockNumber: seg.currentBlockNumber,
		ChunkOffset: int64(seg.currentBlockSize),
	}

	dataSize := uint32(len(data))
	// The entire chunk can fit into the block.
	if seg.currentBlockSize+dataSize+chunkHeaderSize <= blockSize {
		seg.appendChunkBuffer(chunkBuffer, data, ChunkTypeFull)
		position.ChunkSize = dataSize + chunkHeaderSize
	} else {
		// If the size of the data exceeds the size of the block,
		// the data should be written to the block in batches.
		var (
			leftSize             = dataSize
			blockCount    uint32 = 0
			currBlockSize        = seg.currentBlockSize
		)

		for leftSize > 0 {
			chunkSize := blockSize - currBlockSize - chunkHeaderSize
			if chunkSize > leftSize {
				chunkSize = leftSize
			}

			var end = dataSize - leftSize + chunkSize
			if end > dataSize {
				end = dataSize
			}

			// append the chunks to the buffer
			var chunkType ChunkType
			switch leftSize {
			case dataSize: // First chunk
				chunkType = ChunkTypeFirst
			case chunkSize: // Last chunk
				chunkType = ChunkTypeLast
			default: // Middle chunk
				chunkType = ChunkTypeMiddle
			}
			seg.appendChunkBuffer(chunkBuffer, data[dataSize-leftSize:end], chunkType)

			leftSize -= chunkSize
			blockCount += 1
			currBlockSize = (currBlockSize + chunkSize + chunkHeaderSize) % blockSize
		}
		position.ChunkSize = blockCount*chunkHeaderSize + dataSize
	}

	// the buffer length must be equal to chunkSize+padding length
	endBufferLen := chunkBuffer.Len()
	if position.ChunkSize+padding != uint32(endBufferLen-startBufferLen) {
		return nil, fmt.Errorf("wrong!!! the chunk size %d is not equal to the buffer len %d",
			position.ChunkSize+padding, endBufferLen-startBufferLen)
	}

	// update segment status
	seg.currentBlockSize += position.ChunkSize
	if seg.currentBlockSize >= blockSize {
		seg.currentBlockNumber += seg.currentBlockSize / blockSize
		seg.currentBlockSize = seg.currentBlockSize % blockSize
	}

	return position, nil
}

// writeAll write batch data to the segment file.
func (seg *segment) writeAll(data [][]byte) (positions []*ChunkPosition, err error) {
	if seg.closed {
		return nil, ErrClosed
	}

	// if any error occurs, restore the segment status
	originBlockNumber := seg.currentBlockNumber
	originBlockSize := seg.currentBlockSize

	// init chunk buffer
	chunkBuffer := bytebufferpool.Get()
	chunkBuffer.Reset()
	defer func() {
		if err != nil {
			seg.currentBlockNumber = originBlockNumber
			seg.currentBlockSize = originBlockSize
		}
		bytebufferpool.Put(chunkBuffer)
	}()

	// write all data to the chunk buffer
	var pos *ChunkPosition
	positions = make([]*ChunkPosition, len(data))
	for i := 0; i < len(positions); i++ {
		pos, err = seg.writeToBuffer(data[i], chunkBuffer)
		if err != nil {
			return
		}
		positions[i] = pos
	}
	// write the chunk buffer to the segment file
	if err = seg.writeChunkBuffer(chunkBuffer); err != nil {
		return
	}
	return
}

// Write writes the data to the segment file.
func (seg *segment) Write(data []byte) (pos *ChunkPosition, err error) {
	if seg.closed {
		return nil, ErrClosed
	}

	originBlockNumber := seg.currentBlockNumber
	originBlockSize := seg.currentBlockSize

	// init chunk buffer
	chunkBuffer := bytebufferpool.Get()
	chunkBuffer.Reset()
	defer func() {
		if err != nil {
			seg.currentBlockNumber = originBlockNumber
			seg.currentBlockSize = originBlockSize
		}
		bytebufferpool.Put(chunkBuffer)
	}()

	// write all data to the chunk buffer
	pos, err = seg.writeToBuffer(data, chunkBuffer)
	if err != nil {
		return
	}
	// write the chunk buffer to the segment file
	if err = seg.writeChunkBuffer(chunkBuffer); err != nil {
		return
	}

	return
}

func (seg *segment) appendChunkBuffer(buf *bytebufferpool.ByteBuffer, data []byte, chunkType ChunkType) {
	// Length	2 Bytes	index:4-5
	binary.LittleEndian.PutUint16(seg.header[4:6], uint16(len(data)))
	// Type	1 Byte	index:6
	seg.header[6] = chunkType
	// Checksum	4 Bytes index:0-3
	sum := crc32.ChecksumIEEE(seg.header[4:])
	sum = crc32.Update(sum, crc32.IEEETable, data)
	binary.LittleEndian.PutUint32(seg.header[:4], sum)

	// append the header and data to segment chunk buffer
	buf.B = append(buf.B, seg.header...)
	buf.B = append(buf.B, data...)
}

// write the pending chunk buffer to the segment file
func (seg *segment) writeChunkBuffer(buf *bytebufferpool.ByteBuffer) error {
	if seg.currentBlockSize > blockSize {
		return errors.New("the current block size exceeds the maximum block size")
	}

	// write the data into underlying file
	if _, err := seg.fd.Write(buf.Bytes()); err != nil {
		return err
	}

	// the cached block can not be reused again after writes.
	seg.startupBlock.blockNumber = -1
	return nil
}

// Read reads the data from the segment file by the block number and chunk offset.
func (seg *segment) Read(blockNumber uint32, chunkOffset int64) ([]byte, error) {
	value, _, err := seg.readInternal(blockNumber, chunkOffset)
	return value, err
}

func (seg *segment) readInternal(blockNumber uint32, chunkOffset int64) ([]byte, *ChunkPosition, error) {
	if seg.closed {
		return nil, nil, ErrClosed
	}

	var (
		result    []byte
		block     []byte
		segSize   = seg.Size()
		nextChunk = &ChunkPosition{SegmentId: seg.id}
	)

	if seg.isStartupTraversal {
		block = seg.startupBlock.block
	} else {
		block = getBuffer()
		if len(block) != blockSize {
			block = make([]byte, blockSize)
		}
		defer putBuffer(block)
	}

	for {
		size := int64(blockSize)
		offset := int64(blockNumber) * blockSize
		if size+offset > segSize {
			size = segSize - offset
		}

		if chunkOffset >= size {
			return nil, nil, io.EOF
		}

		if seg.isStartupTraversal {
			// There are two cases that we should read block from file:
			// 1. the acquired block is not the cached one
			// 2. new writes appended to the block, and the block
			// is still smaller than 32KB, we must read it again because of the new writes.
			if seg.startupBlock.blockNumber != int64(blockNumber) || size != blockSize {
				// read block from segment file at the specified offset.
				_, err := seg.fd.ReadAt(block[0:size], offset)
				if err != nil {
					return nil, nil, err
				}
				// remember the block
				seg.startupBlock.blockNumber = int64(blockNumber)
			}
		} else {
			if _, err := seg.fd.ReadAt(block[0:size], offset); err != nil {
				return nil, nil, err
			}
		}

		// header
		header := block[chunkOffset : chunkOffset+chunkHeaderSize]

		// length
		length := binary.LittleEndian.Uint16(header[4:6])

		// copy data
		start := chunkOffset + chunkHeaderSize
		result = append(result, block[start:start+int64(length)]...)

		// check sum
		checksumEnd := chunkOffset + chunkHeaderSize + int64(length)
		checksum := crc32.ChecksumIEEE(block[chunkOffset+4 : checksumEnd])
		savedSum := binary.LittleEndian.Uint32(header[:4])
		if savedSum != checksum {
			return nil, nil, ErrInvalidCRC
		}

		// type
		chunkType := header[6]

		if chunkType == ChunkTypeFull || chunkType == ChunkTypeLast {
			nextChunk.BlockNumber = blockNumber
			nextChunk.ChunkOffset = checksumEnd
			// If this is the last chunk in the block, and the left block
			// space are paddings, the next chunk should be in the next block.
			if checksumEnd+chunkHeaderSize >= blockSize {
				nextChunk.BlockNumber += 1
				nextChunk.ChunkOffset = 0
			}
			break
		}
		blockNumber += 1
		chunkOffset = 0
	}
	return result, nextChunk, nil
}

// Next returns the Next chunk data.
// You can call it repeatedly until io.EOF is returned.
func (segReader *segmentReader) Next() ([]byte, *ChunkPosition, error) {
	// The segment file is closed
	if segReader.segment.closed {
		return nil, nil, ErrClosed
	}

	// this position describes the current chunk info
	chunkPosition := &ChunkPosition{
		SegmentId:   segReader.segment.id,
		BlockNumber: segReader.blockNumber,
		ChunkOffset: segReader.chunkOffset,
	}

	value, nextChunk, err := segReader.segment.readInternal(
		segReader.blockNumber,
		segReader.chunkOffset,
	)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the chunk size.
	// Remember that the chunk size is just an estimated value,
	// not accurate, so don't use it for any important logic.
	chunkPosition.ChunkSize =
		nextChunk.BlockNumber*blockSize + uint32(nextChunk.ChunkOffset) -
			(segReader.blockNumber*blockSize + uint32(segReader.chunkOffset))

	// update the position
	segReader.blockNumber = nextChunk.BlockNumber
	segReader.chunkOffset = nextChunk.ChunkOffset

	return value, chunkPosition, nil
}

// Encode encodes the chunk position to a byte slice.
// Return the slice with the actual occupied elements.
// You can decode it by calling wal.DecodeChunkPosition().
func (cp *ChunkPosition) Encode() []byte {
	return cp.encode(true)
}

// EncodeFixedSize encodes the chunk position to a byte slice.
// Return a slice of size "maxLen".
// You can decode it by calling wal.DecodeChunkPosition().
func (cp *ChunkPosition) EncodeFixedSize() []byte {
	return cp.encode(false)
}

// encode the chunk position to a byte slice.
func (cp *ChunkPosition) encode(shrink bool) []byte {
	buf := make([]byte, maxLen)

	var index = 0
	// SegmentId
	index += binary.PutUvarint(buf[index:], uint64(cp.SegmentId))
	// BlockNumber
	index += binary.PutUvarint(buf[index:], uint64(cp.BlockNumber))
	// ChunkOffset
	index += binary.PutUvarint(buf[index:], uint64(cp.ChunkOffset))
	// ChunkSize
	index += binary.PutUvarint(buf[index:], uint64(cp.ChunkSize))
	// ValueNum
	index += binary.PutUvarint(buf[index:], uint64(cp.ValueNum))

	if shrink {
		return buf[:index]
	}
	return buf
}

// DecodeChunkPosition decodes the chunk position from a byte slice.
// You can encode it by calling wal.ChunkPosition.Encode().
func DecodeChunkPosition(buf []byte) *ChunkPosition {
	if len(buf) == 0 {
		return nil
	}

	var index = 0
	// SegmentId
	segmentId, n := binary.Uvarint(buf[index:])
	index += n
	// BlockNumber
	blockNumber, n := binary.Uvarint(buf[index:])
	index += n
	// ChunkOffset
	chunkOffset, n := binary.Uvarint(buf[index:])
	index += n
	// ChunkSize
	chunkSize, n := binary.Uvarint(buf[index:])
	index += n
	// ValueNum
	ValueNum, n := binary.Uvarint(buf[index:])
	index += n

	return &ChunkPosition{
		SegmentId:   uint32(segmentId),
		BlockNumber: uint32(blockNumber),
		ChunkOffset: int64(chunkOffset),
		ChunkSize:   uint32(chunkSize),
		ValueNum:    int64(ValueNum),
	}
}

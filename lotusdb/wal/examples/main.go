package main

import (
	"fmt"
	"io"
	"log"

	"github.com/rosedblabs/wal"
)

func main() {
	walFile, _ := wal.Open(wal.DefaultOptions)
	// write some data
	chunkPosition, _ := walFile.Write([]byte("some data 1"), nil)
	// read by the position
	val, _, _ := walFile.Read(chunkPosition)
	fmt.Println(string(val))

	_, err := walFile.Write([]byte("some data 2"), nil)
	if err != nil {
		log.Println(err)
	}
	_, err = walFile.Write([]byte("some data 3"), nil)
	if err != nil {
		log.Println(err)
	}

	// iterate all data in wal
	reader := walFile.NewReader()
	for {
		val, _, pos, err := reader.Next()
		if err == io.EOF {
			break
		}
		fmt.Println(string(val))
		fmt.Println(pos) // get position of the data for next read
	}
}

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const (
	SBFS_NUM_FILES          = 12
	SBFS_NUM_HEADER_OFFSETS = 2
	// initial 0x10000 bytes of the dump contains some data that is not part of SBFS
	NOR_HEADER_SIZE = 0x010000
)

var (
	// flags
	inputFile      = flag.String("f", "sbfs.img", "input file")
	outputDir      = flag.String("x", "", "output directory")
	changeSequence = flag.String("s", "", "Change sequence number. Hex value required")

	// SBFS file names
	sbfsFileNames = []string{
		"smcfw.bin",
		"psp1sp.bin",
		"speaker.bin",
		"smcerr.log",
		"smc_d.cfg",
		"certkeys.smc",
	}

	// potential header offsets
	sbfsHeaderOffsets = []int64{
		0x10000,
		0x11000,
	}

	// magic string
	sbfsMagic = "SFBS"
)

type sfbsFile struct {
	Offset  uint32
	Length  uint32
	Unknown [8]byte
}

type sbfsHeader struct {
	Magic          [4]byte
	FormatVersion  byte
	SequenceNumber byte
	LayoutVersion  byte
	Unknown1       byte
	Unknown2       [24]byte
	Files          [SBFS_NUM_FILES]sfbsFile
}

type sbfsHeaderWithSha struct {
	Header   sbfsHeader
	Checksum [32]byte
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func reverseString(str string) (result string) {
	// iterate over str and prepend to result
	for _, v := range str {
		result = string(v) + result
	}
	return
}

func main() {
	flag.Parse()
	var newSeq uint8
	var injectMode bool = false

	// flags and sanity checks
	if isFlagPassed("s") {
		_, err := fmt.Sscanf(*changeSequence, "0x%x", &newSeq)
		if err != nil {
			log.Fatal("Invalid sequence number: ", err)
		}
		injectMode = true
	}
	// create output dir if needed
	if isFlagPassed("x") {
		if _, err := os.Stat(*outputDir); errors.Is(err, os.ErrNotExist) {
			if err = os.Mkdir(*outputDir, os.ModePerm); err != nil {
				log.Fatal(err)
			}
		}
	}

	file, err := os.Open(*inputFile)
	if err != nil {
		log.Fatal("Error opening input file: ", err)
	}
	defer file.Close()

	var header sbfsHeaderWithSha
	var actualHeaderOffset int64 = 0x00
	for i := 0; i < SBFS_NUM_HEADER_OFFSETS; i++ {
		_, err = file.Seek(sbfsHeaderOffsets[i], 0)
		if err != nil {
			log.Fatal(err)
		}

		err = binary.Read(file, binary.LittleEndian, &header)
		if err != nil {
			log.Fatal(err)
		}
		// check if it's axctual header
		if string(header.Header.Magic[:]) == sbfsMagic {
			actualHeaderOffset = sbfsHeaderOffsets[i]
			break
		}
	}
	if actualHeaderOffset == 0x00 {
		log.Fatal("Invalid file. Could not find valid header\n")
	}

	// in injectMode we do not output info
	if !injectMode {
		fmt.Printf("\n=== SBFS Header ===\n")
		fmt.Printf("%16s: %s (at offset: 0x%06X)\n", "Magic", reverseString(string(header.Header.Magic[:])), actualHeaderOffset)
		fmt.Printf("%16s: 0x%02X\n", "Format Version", header.Header.FormatVersion)
		fmt.Printf("%16s: 0x%02X\n", "Sequence Number", header.Header.SequenceNumber)
		fmt.Printf("%16s: 0x%02X\n", "Layout Version", header.Header.LayoutVersion)
		fmt.Printf("%16s: 0x%02X\n", "SHA", header.Checksum)

		// copy initial chunk of data
		if isFlagPassed("x") {
			var fout *os.File
			fullFilePath := filepath.Join(*outputDir, "data.hdr")
			fout, err = os.Create(fullFilePath)
			if err != nil {
				log.Fatal(err)
			}
			_, err = file.Seek(0x0, 0)
			if err != nil {
				log.Fatal(err)
			}
			_, err = io.CopyN(fout, file, 0x10000)
			fout.Close()
		}

		fmt.Printf("\n=== SBFS Files ===\n")
		for i := 0; i < SBFS_NUM_FILES; i++ {
			filePtr := header.Header.Files[i]
			if filePtr.Length == 0x00 {
				continue
			}
			fmt.Printf("%16s %10s:0x%06X %10s:0x%06X\n", sbfsFileNames[i], "Offset", filePtr.Offset*0x1000, "Length", filePtr.Length*0x1000)
			if isFlagPassed("x") {
				var fout *os.File
				fullFilePath := filepath.Join(*outputDir, sbfsFileNames[i])
				fout, err = os.Create(fullFilePath)
				if err != nil {
					log.Fatal(err)
				}
				_, err = file.Seek(int64(filePtr.Offset)*0x1000, 0)
				if err != nil {
					log.Fatal(err)
				}
				_, err = io.CopyN(fout, file, int64(filePtr.Length)*0x1000)
				fout.Close()
			}
		}
		fmt.Printf("\n")
		return
	}
	// inject mode
	fmt.Printf("\n=== Updating SBFS ===\n")

	// modify header
	if isFlagPassed("s") {
		header.Header.SequenceNumber = newSeq
		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.LittleEndian, header.Header)
		if err != nil {
			log.Fatal(err)
		}
		header.Checksum = sha256.Sum256(buf.Bytes())
		fmt.Printf("%20s: 0x%02X\n", "New Sequence number", newSeq)
		fmt.Printf("%20s: 0x%02X\n", "New SHA256 checksum", header.Checksum)
	}

	// write everything out
	var fout *os.File
	outFileName := *inputFile + ".out"
	fout, err = os.Create(outFileName)
	if err != nil {
		log.Fatal(err)
	}
	// copy up to header
	_, err = file.Seek(0, 0)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.CopyN(fout, file, actualHeaderOffset)
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, header)
	if err != nil {
		log.Fatal(err)
	}
	_, err = fout.Write(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	// copy the rest of the sbfs
	_, err = file.Seek(actualHeaderOffset+int64(len(buf.Bytes())), 0)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(fout, file)
	if err != nil {
		log.Fatal(err)
	}
	fout.Close()

	fmt.Printf("\nSBFS written to: %s\n", outFileName)
	fmt.Printf("\n")
}

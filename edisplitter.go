// edisplitter.go
package edisplitter

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/howeyc/crc16"
)

var afSequenceNumChk uint16
var seqErrTime time.Time = time.Now()
var allDabSrvComplete = false
var mVerbose = false

var mEdiPtr = 1 //EDI AF ProtocolType and Version, experimental feature to reduce EDI overhead

func SetVerbosity(verbose bool) {
	mVerbose = verbose
}

func SetAfVersion(afVersion int) {
	mEdiPtr = afVersion
}

func ParseEdiData(ediInputchan chan []byte) {
	for {
		//Receive from channel
		ediData, open := <-ediInputchan
		if !open {
			fmt.Println("Channel was closed")
			return
		}

		ediReader := bytes.NewReader(ediData)

		var afPacketTagByteVal []byte = make([]byte, 2)
		_, err := ediReader.Read(afPacketTagByteVal)
		if err != nil {
			if mVerbose { if mVerbose { fmt.Printf("Error reading from EdiInput: %s\n", err) } }
		}

		tagValString := string(afPacketTagByteVal)
		if tagValString == "PF" {
			fmt.Println("PF used")

			var pSeqBytes []byte = make([]byte, 2)
			_, err = ediReader.Read(pSeqBytes)
			if err != nil {
				continue
			}

			pSeq := binary.BigEndian.Uint16(pSeqBytes)
			if mVerbose { if mVerbose { fmt.Printf("PF PSeq: %d\n", pSeq) } }

			var fIndexBytes []byte = make([]byte, 3)
			_, err = ediReader.Read(fIndexBytes)
			if err != nil {
				continue
			}

			fIndex := binary.BigEndian.Uint32(fIndexBytes)
			if mVerbose { fmt.Printf("FragmentIndex: %d\n", fIndex) }

			_, err = ediReader.Read(fIndexBytes)
			if err != nil {
				continue
			}

			fCount := binary.BigEndian.Uint32(fIndexBytes)
			if mVerbose { fmt.Printf("FragmentCount: %d\n", fCount) }

			_, err = ediReader.Read(pSeqBytes)
			if err != nil {
				continue
			}

			var fecFlag bool = ((pSeqBytes[0] & 0x80) >> 7) != 0
			var addrFlag bool = ((pSeqBytes[0] & 0x40) >> 6) != 0
			if mVerbose { fmt.Printf("FEC Used: %d, AddrUsed: %d\n", fecFlag, addrFlag) }

			pSeqBytes[0] |= 0 << 7
			pSeqBytes[0] |= 0 << 6

			payloadLen := binary.BigEndian.Uint16(pSeqBytes)
			if mVerbose { fmt.Printf("PayloadLen: %d\n", payloadLen) }

			if fecFlag {
				rsK, _ := ediReader.ReadByte()
				rsZ, _ := ediReader.ReadByte()
				if mVerbose { fmt.Printf("RSk: %d, RSz: %d\n", rsK, rsZ) }
			}

			if addrFlag {
				_, err = ediReader.Read(pSeqBytes)
				if err != nil {
					continue
				}

				source := binary.BigEndian.Uint16(pSeqBytes)

				_, err = ediReader.Read(pSeqBytes)
				if err != nil {
					continue
				}

				destination := binary.BigEndian.Uint16(pSeqBytes)

				if mVerbose { fmt.Printf("Source: %d, Destination: %d\n", source, destination) }
			}

			//HCRC
			ediReader.Read(pSeqBytes)
		}

		if tagValString == "AF" {
			var afPacketLenBytes []byte = make([]byte, 4)
			_, err = ediReader.Read(afPacketLenBytes)
			if err != nil {
				continue
			}

			afPayloadLength := binary.BigEndian.Uint32(afPacketLenBytes)
			if ediReader.Len() < (int)(afPayloadLength) {
				if mVerbose { fmt.Printf("Not enough AF Data: %d - %d\n", ediReader.Len(), afPayloadLength) }
				continue
			}

			var afSeqBytes []byte = make([]byte, 2)
			_, err = ediReader.Read(afSeqBytes)
			if err != nil {
				continue
			}

			afSequenceNum := binary.BigEndian.Uint16(afSeqBytes)

			if afSequenceNum != (afSequenceNumChk+1)&0xFFFF {
				curTime := time.Now()
				elapsed := curTime.Sub(seqErrTime)

				seqErrTime = curTime
				if mVerbose { fmt.Printf("AF Sequence broken, is: %d, should be: %d, QueueChan: %d, LastErr: %d - %f\n", afSequenceNum, (afSequenceNumChk + 1), len(ediInputchan), elapsed.Nanoseconds(), elapsed.Seconds()) }
			}

			afSequenceNumChk = afSequenceNum

			nextByte, err := ediReader.ReadByte()
			if err != nil {
				continue
			}

			var crcFlag bool = ((nextByte & 0x80) >> 7) != 0
			if crcFlag {
				//TODO FullEdi
				//crc1 := ediData[10 + afPayloadLength]
				//crc2 := ediData[10 + afPayloadLength+1]
				//fmt.Printf("AF SeqNum: %d - CRC: 0x%02x%02x - FrameLen: %d\n", afSequenceNum, crc1, crc2, len(ediData))
				//TODO FUllEdi
				chkSumFull := crc16.ChecksumCCITTFalse(ediData)
				if chkSumFull != 0x1D0F {
					if mVerbose { fmt.Printf("AF CRC CheckSum mismatch: 0x%04X\n", chkSumFull) }
					fmt.Printf("AF CRC CheckSum mismatch: 0x%04X\n", chkSumFull)
					continue
				}
			}

			protocolType, _ := ediReader.ReadByte()

			//Protocol type. 'T' means Tag Packets
			if protocolType == 'T' {
				//Read till CRC
				for (ediReader.Len() - 2) > 0 {
					startPos, _ := ediReader.Seek(0, os.SEEK_CUR)

					//TagName
					var tagNameBytes []byte = make([]byte, 4)
					_, err := ediReader.Read(tagNameBytes)
					if err != nil {
						continue
					}

					tagName := string(tagNameBytes)

					//TagLength
					_, err = ediReader.Read(tagNameBytes)
					if err != nil {
						continue
					}

					tagLength := binary.BigEndian.Uint32(tagNameBytes) / 8

					payLoadbytes := make([]byte, tagLength)
					_, err = ediReader.Read(payLoadbytes)
					if err != nil {
						continue
					}

					if tagName == "deti" {
						if allDabSrvComplete {
							for _, dabSrvPtr := range mDabNewServicesPtr {
								dabSrvPtr.DetiFields = ediData[startPos+8 : startPos+8+6]
							}
						}
						parseDetiData(payLoadbytes)
					}

					if tagName[0] == 'e' && tagName[1] == 's' && tagName[2] == 't' {
						subChanId := (payLoadbytes[0] & 0xFC) >> 2

						if allDabSrvComplete {
							//mstLen := tagLength-3
							estPayload := payLoadbytes[3:tagLength]

							mSubchannels[subChanId].MscInput <- MscAf{
								afSequenceNum: afSequenceNum,
								afData:        estPayload,
							}

							FindDabSrv:
							for _, dabSrvPtr := range mDabNewServicesPtr {
								for _, srvCompPtr := range dabSrvPtr.DabServiceComponents {
									if srvCompPtr.Subchannel.SubchannelId == subChanId {
										if len(dabSrvPtr.DetiFields) == 0 {
											break FindDabSrv
										}

										dabSrvPtr.EstData = ediData[startPos : startPos+(int64)(tagLength)+3+4+1] // +3 bytes SSTC, +4 byte est<n>, +1 for syntax of slice

										//Set Substream number to 1
										dabSrvPtr.EstData[3] = 0x01

										afSequenceNumBytes := make([]byte, 2)
										binary.BigEndian.PutUint16(afSequenceNumBytes, afSequenceNum)
										afFrame := recreateAF(dabSrvPtr, afSequenceNumBytes)

										select {
										case dabSrvPtr.AfFrameOutput <- afFrame:
										case <-time.After(time.Second):
											if mVerbose { fmt.Printf("NoData for Service: 0x%04X - %s\n", dabSrvPtr.ServiceId, dabSrvPtr.ServiceLabel) }
											_ = <-dabSrvPtr.AfFrameOutput
										default:
											continue

										}

										break FindDabSrv
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

var (
	MPendingToggle = make(map[uint8]*DynamicLabel)
	MPendingToggleMutex = sync.RWMutex{}
)

func InsertCustomLiveTag(afFrame []byte, customTag []byte) (customizedAfFrame []byte) {
	if len(customTag) == 0 || len(afFrame) < 12 {
		return afFrame
	}

	afSync := []byte("AF")
	customizedAfFrame = append(customizedAfFrame, afSync[:]...)

	lenOrigAfFrameBytes := binary.BigEndian.Uint32(afFrame[2:6])
	lenCustomTagBytes := uint32(len(customTag))

	lenCustomizedAf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenCustomizedAf, lenOrigAfFrameBytes+lenCustomTagBytes)

	//insert new AF length
	customizedAfFrame = append(customizedAfFrame, lenCustomizedAf...)

	//Copy SEQ, AR, PT
	customizedAfFrame = append(customizedAfFrame, afFrame[6:10]...)
	//insert new custom tag
	customizedAfFrame = append(customizedAfFrame, customTag...)
	//insert old tags data
	customizedAfFrame = append(customizedAfFrame, afFrame[10:len(afFrame)-2]...)

	customizedAfCrc := crc16.ChecksumCCITTFalse(customizedAfFrame) ^ 0xFFFF
	customizedAfCrcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(customizedAfCrcBytes, customizedAfCrc)

	customizedAfFrame = append(customizedAfFrame, customizedAfCrcBytes...)

	//fmt.Printf("CustTagBOrig: %d 0x%X\n", len(afFrame), afFrame)
	//fmt.Printf("CustTagBCust: %d 0x%X\n\n", len(customizedAfFrame), customizedAfFrame)

	return
}

func CreateDlptTag(dLabel *DynamicLabel) (dlptTag []byte) {
	jsonData, jsonErr := json.Marshal(*dLabel)
	if jsonErr != nil {
		dlptTag = nil
	}

	//4 bytes Tag name
	dlptTag = append(dlptTag, []byte("dlpt")...)
	//4 bytes tag length in bits
	tagLenBits := make([]byte, 4)
	binary.BigEndian.PutUint32(tagLenBits, uint32(len(jsonData) * 8))
	if mVerbose { fmt.Printf("DLPTag Length: %d - 0x%08X\n", len(jsonData), tagLenBits) }

	dlptTag = append(dlptTag, tagLenBits...)
	dlptTag = append(dlptTag, jsonData...)

	if mVerbose { fmt.Printf("DLPTag: 0x%X - %s\n", dlptTag, dlptTag) }

	return
}

// *ptr Tag, MajorVersion 0, MinorVersion 0
var EDI_PTR_TAG_0_0 = []byte{0x2A, 0x70, 0x74, 0x72, 0x00, 0x00, 0x00, 0x40, 0x44, 0x45, 0x54, 0x49, 0x00, 0x00, 0x00, 0x00}

// *ptr Tag, MajorVersion 1, MinorVersion 0
var EDI_PTR_TAG_1_0 = []byte{0x2A, 0x70, 0x74, 0x72, 0x00, 0x00, 0x00, 0x40, 0x44, 0x45, 0x54, 0x49, 0x00, 0x01, 0x00, 0x00}

/* Edi Frame Assembling */
func recreateAF(dabSrvPtr *DabSrv, seqbytes []byte) (aFrame []byte) {
	aFrame = append(aFrame, []byte("AF")...)

	var afPayLoad []byte
	if mEdiPtr == 0 {
		afPayLoad = append(afPayLoad, EDI_PTR_TAG_0_0...)
	}

	if mEdiPtr == 0 || dabSrvPtr.Figs.writeFig0_10 {
		detiTag := recreateDetiTag(dabSrvPtr)
		if detiTag != nil {
			afPayLoad = append(afPayLoad, detiTag...)
		}
	}

	afPayLoad = append(afPayLoad, dabSrvPtr.EstData...)

	var afPayloadLen = (uint32)(len(afPayLoad))
	tagLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tagLen, afPayloadLen)

	aFrame = append(aFrame, tagLen[:]...)
	aFrame = append(aFrame, seqbytes[:]...)

	aFrame = append(aFrame, 0x90) // CRC Flag CF 1 bit, MAJ 3 bits, MIN 4 bits
	aFrame = append(aFrame, 0x54) // T (PT Protocoltype, for TAG Packets, the value shall be the ASCII representation of "T")

	aFrame = append(aFrame, afPayLoad[:]...)

	afCrc := crc16.ChecksumCCITTFalse(aFrame) ^ 0xFFFF
	afCrcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(afCrcBytes, afCrc)

	aFrame = append(aFrame, afCrcBytes[:]...)

	return
}

//Creates an Application Frame containing only 'deti' Tags. There may be more than one 'deti' Tag inside the AF if the complete FIC data doesn't fit into the 3*30 bytes of the FIC fields
func CreateDetiAF(dabSrvPtr *DabSrv) (aFrame []byte) {
	aFrame = append(aFrame, []byte("AF")...)

	var afPayLoad []byte

	dabSrvPtr.ficReset()

	for {
		detiTag := recreateDetiTag(dabSrvPtr)
		if detiTag != nil {
			afPayLoad = append(afPayLoad, detiTag...)
		} else {
			break
		}
	}

	var afPayloadLen = (uint32)(len(afPayLoad))
	tagLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tagLen, afPayloadLen)

	aFrame = append(aFrame, tagLen[:]...)
	aFrame = append(aFrame, []byte{0x00, 0x00}...)

	aFrame = append(aFrame, 0x90) //CF 1 bit, MAJ 3 bits, MIN 4 bits - CRC present
	aFrame = append(aFrame, 0x54) // T (PT Protocoltype, for TAG Packets, the value shall be the ASCII representation of "T")

	aFrame = append(aFrame, afPayLoad[:]...)

	afCrc := crc16.ChecksumCCITTFalse(aFrame) ^ 0xFFFF
	afCrcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(afCrcBytes, afCrc)

	aFrame = append(aFrame, afCrcBytes[:]...)

	return
}

func recreateDetiTag(dabSrvPtr *DabSrv) (detiTag []byte) {
	detiTag = append(detiTag, []byte("deti")...)

	fibs := recreateFibs(dabSrvPtr)

	tagLen := make([]byte, 4)
	var tagBitLen uint32
	var flagField byte
	if fibs == nil {
		tagBitLen = (2 + 4) * 8 //FIC field not present
		flagField = 0x00
	} else {
		tagBitLen = (2 + 4 + 96) * 8 //FIC field present
		flagField = 0x40
	}

	binary.BigEndian.PutUint32(tagLen, tagBitLen)
	detiTag = append(detiTag, tagLen[:]...)

	flagField |= dabSrvPtr.DetiFields[0] & 0x1F

	detiTag = append(detiTag, flagField)
	//ETI header
	detiTag = append(detiTag, dabSrvPtr.DetiFields[1:]...)

	if fibs != nil {
		detiTag = append(detiTag, fibs...)
	} else {
		return nil
	}

	return
}

func (dabSrv *DabSrv) ficReset() {
	dabSrv.Figs.Fig_1_00_done = false
	dabSrv.Figs.Fig_0_09_done = false
	dabSrv.Figs.Fig_1_01_done = false
	dabSrv.Figs.Fig_1_05_done = false
	for _, comp := range dabSrv.DabServiceComponents {
		comp.FIG_1_04_done = false
		comp.FIG_0_02_done = false
		comp.FIG_0_08_done = false

		comp.Subchannel.Fig_0_01_done = false
		comp.Subchannel.FIG_0_14_done = false

		for _, uapp := range comp.UserApplications {
			uapp.FIG_1_06_done = false
			uapp.FIG_0_13_done = false
		}
	}
}

func (dabSrvComp *DabSrvComponent) mergeFig013() (completeFigFromUapps []byte) {
	if len(dabSrvComp.UserApplications) == 0 {
		return
	}

	var serviceIdBytes []byte
	isDataService := dabSrvComp.ASCTy == 0xFF
	if !isDataService {
		serviceIdBytes = dabSrvComp.UserApplications[0].FIG_0_13[0:2]
	} else {
		serviceIdBytes = dabSrvComp.UserApplications[0].FIG_0_13[0:4]
	}

	completeFigFromUapps = []byte{0x00, 0x0D}
	completeFigFromUapps = append(completeFigFromUapps, serviceIdBytes...)
	completeFigFromUapps = append(completeFigFromUapps, 0x00) //numUserApps
	var numUapps byte
	for _, uApp := range dabSrvComp.UserApplications {
		numUapps++
		if !isDataService {
			appData := uApp.FIG_0_13[5:]
			completeFigFromUapps = append(completeFigFromUapps, appData...)
		} else {
			appData := uApp.FIG_0_13[7:]
			completeFigFromUapps = append(completeFigFromUapps, appData...)
		}
	}

	completeFigFromUapps[0] = byte(len(completeFigFromUapps) - 1)

	if !isDataService {
		completeFigFromUapps[4] = numUapps
	} else {
		completeFigFromUapps[6] = numUapps
	}

	return
}

var mStripDataComponents = true
func recreateFibs(dabSrvPtr *DabSrv) (ficField []byte) {
	var fib0 []byte
	var fibBytesLeft = 30

	for i:= 0; i < 3; i++ {
		/*
			In any 96 ms period, the FIG 0/0 shall be transmitted in a fixed time position. In transmission mode I, this shall be the
			first FIB (of the three) associated with the first CIF (of the four) in the transmission frame. The FIG 0/0
			shall be the first FIG in the FIB.
		*/
		if dabSrvPtr.Figs.writeFig0_00 {
			fib0 = append(fib0, dabSrvPtr.Figs.Fig_0_00...)
			dabSrvPtr.Figs.writeFig0_00 = false

			fibBytesLeft -= len(dabSrvPtr.Figs.Fig_0_00)
		}

		if dabSrvPtr.Figs.writeFig0_10 {
			fib0 = append(fib0, dabSrvPtr.Figs.Fig_0_10...)
			dabSrvPtr.Figs.writeFig0_10 = false

			fibBytesLeft -= len(dabSrvPtr.Figs.Fig_0_10)
		}

		for _, srvComp := range dabSrvPtr.DabServiceComponents {
			if mStripDataComponents {
				if srvComp.ASCTy != 0xFF {
					//Subchannel Data
					if !srvComp.Subchannel.Fig_0_01_done {
						fib0 = append(fib0, srvComp.Subchannel.Fig_0_01...)
						srvComp.Subchannel.Fig_0_01_done = true

						fibBytesLeft -= len(srvComp.Subchannel.Fig_0_01)
					}

					//Service Component Global definition
					if !srvComp.FIG_0_02_done {
						if fibBytesLeft >= len(srvComp.FIG_0_02) {
							fib0 = append(fib0, srvComp.FIG_0_02...)
							srvComp.FIG_0_02_done = true

							fibBytesLeft -= len(srvComp.FIG_0_02)
						} else {
							goto FinishFIB
						}
					}

					if !srvComp.FIG_0_08_done {
						if fibBytesLeft >= len(srvComp.FIG_0_08) {
							fib0 = append(fib0, srvComp.FIG_0_08...)
							srvComp.FIG_0_08_done = true

							fibBytesLeft -= len(srvComp.FIG_0_08)
						} else {
							goto FinishFIB
						}
					}

					for _, uApp := range srvComp.UserApplications {
						if uApp.IsXpadApp {
							if !uApp.FIG_0_13_done {
								if fibBytesLeft >= len(uApp.FIG_0_13) {
									fib0 = append(fib0, uApp.FIG_0_13...)
									uApp.FIG_0_13_done = true
									fibBytesLeft -= len(uApp.FIG_0_13)
								} else {
									goto FinishFIB
								}
							}

							if !uApp.FIG_1_06_done {
								if len(uApp.FIG_1_06) > 0 {
									if fibBytesLeft >= len(uApp.FIG_1_06) {
										fib0 = append(fib0, uApp.FIG_1_06...)
										uApp.FIG_1_06_done = true
										fibBytesLeft -= len(uApp.FIG_1_06)
									} else {
										goto FinishFIB
									}
								} else {
									uApp.FIG_1_06_done = true
								}
							}
						} else {
						}
					}
				} else {
				}
			} else {

			}
		}

		if !dabSrvPtr.Figs.Fig_0_09_done {
			if fibBytesLeft >= len(dabSrvPtr.Figs.Fig_0_09) {
				fib0 = append(fib0, dabSrvPtr.Figs.Fig_0_09...)
				fibBytesLeft -= len(dabSrvPtr.Figs.Fig_0_09)
				dabSrvPtr.Figs.Fig_0_09_done = true
			} else {
				goto FinishFIB
			}
		}

		//Labels
		if !dabSrvPtr.Figs.Fig_1_00_done {
			if fibBytesLeft >= len(dabSrvPtr.Figs.Fig_1_00) {
				fib0 = append(fib0, dabSrvPtr.Figs.Fig_1_00...)
				dabSrvPtr.Figs.Fig_1_00_done = true
				fibBytesLeft -= len(dabSrvPtr.Figs.Fig_1_00)
			} else {
				goto FinishFIB
			}
		}

		if !dabSrvPtr.Figs.Fig_1_01_done {
			if fibBytesLeft >= len(dabSrvPtr.Figs.Fig_1_01) {
				fib0 = append(fib0, dabSrvPtr.Figs.Fig_1_01...)
				dabSrvPtr.Figs.Fig_1_01_done = true
				fibBytesLeft -= len(dabSrvPtr.Figs.Fig_1_01)
			} else {
				goto FinishFIB
			}
		}

		for _, srvComp := range dabSrvPtr.DabServiceComponents {
			if !srvComp.FIG_1_04_done {
				if len(srvComp.FIG_1_04) > 0 {
					if fibBytesLeft >= len(srvComp.FIG_1_04) {
						fib0 = append(fib0, srvComp.FIG_1_04...)
						srvComp.FIG_1_04_done = true
						fibBytesLeft -= len(srvComp.FIG_1_04)
					} else {
						goto FinishFIB
					}
				} else {
					srvComp.FIG_1_04_done = true
				}
			}

			for _, uApp := range srvComp.UserApplications {
				if uApp.IsXpadApp {
					if !uApp.FIG_0_13_done {
						if fibBytesLeft >= len(uApp.FIG_0_13) {
							fib0 = append(fib0, uApp.FIG_0_13...)
							uApp.FIG_0_13_done = true
							fibBytesLeft -= len(uApp.FIG_0_13)
						} else {
							goto FinishFIB
						}
					}

					if !uApp.FIG_1_06_done {
						if len(uApp.FIG_1_06) > 0 {
							if fibBytesLeft >= len(uApp.FIG_1_06) {
								fib0 = append(fib0, uApp.FIG_1_06...)
								uApp.FIG_1_06_done = true
								fibBytesLeft -= len(uApp.FIG_1_06)
							} else {
								goto FinishFIB
							}
						} else {
							uApp.FIG_1_06_done = true
						}
					}
				}
			}
		}

		FinishFIB:
			finishFib(&fib0)
			ficField = append(ficField, fib0...)
			fib0 = fib0[:0]

			fibBytesLeft = 30
			continue
	}

	if ficField[0] != 0xFF {
		//fmt.Printf("Complete FIBs: %d\n", len(ficField))
		return
	}

	return nil
}

func finishFib(fibFields *[]byte) {
	if len(*fibFields) < 30 {
		*fibFields = append(*fibFields, 0xFF)
	}

	for len(*fibFields) < 30 {
		*fibFields = append(*fibFields, 0x00)
	}

	fibCrc := crc16.ChecksumCCITTFalse(*fibFields) ^ 0xFFFF
	*fibFields = append(*fibFields, (byte)((fibCrc&0xFF00)>>8))
	*fibFields = append(*fibFields, (byte)(fibCrc & 0x00FF))
}

/* EDI file assembling */
func AssembleFioFrame(afFrame []byte) []byte {
	return packInFio(packInAfpf(afFrame))
}

func packInAfpf(afFrame []byte) (afpfFrame []byte) {
	afpfSync := []byte("afpf")
	afpfFrame = append(afpfFrame, afpfSync[:]...)

	var afFrameLen uint32 = (uint32)(len(afFrame) * 8)
	afFrameLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(afFrameLenBytes, afFrameLen)
	afpfFrame = append(afpfFrame, afFrameLenBytes[:]...)

	afpfFrame = append(afpfFrame, afFrame[:]...)

	return
}

func packInFio(afpfFrame []byte) (fioFrame []byte) {
	fioSync := []byte("fio_")
	fioFrame = append(fioFrame, fioSync[:]...)

	var fioFrameLen uint32 = (uint32)(len(afpfFrame) * 8)
	fioFrameLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(fioFrameLenBytes, fioFrameLen)
	fioFrame = append(fioFrame, fioFrameLenBytes[:]...)

	fioFrame = append(fioFrame, afpfFrame[:]...)

	return
}

/* DETI */
func parseDetiData(detiTagData []byte) {
	detiReader := bytes.NewReader(detiTagData)
	nextByte, _ := detiReader.ReadByte()
	atstF := (nextByte >> 7) != 0
	ficF := ((nextByte & 0x40) >> 6) != 0

	//frmCntHigh := nextByte & 0x1F

	nextByte, _ = detiReader.ReadByte()

	//Frame count low
	//frmCntLow := nextByte

	//ETI Header
	nextByte, _ = detiReader.ReadByte()

	nextByte, _ = detiReader.ReadByte()
	var modeId uint8 = (nextByte & 0xC0) >> 6

	mnscBytes := make([]byte, 2)
	detiReader.Read(mnscBytes)

	if atstF {
		detiReader.ReadByte()
		//utco, _ := detiReader.ReadByte()

		secondsBytes := make([]byte, 4)
		detiReader.Read(secondsBytes)
		//seconds := binary.BigEndian.Uint32(secondsBytes)

		tstaBytes := make([]byte, 3)
		detiReader.Read(tstaBytes)
	}

	if ficF {
		var ficBytes []byte
		switch modeId {
		case 1:
			ficBytes = make([]byte, 96)
		case 2:
			ficBytes = make([]byte, 96)
		case 3:
			ficBytes = make([]byte, 128)
		case 4:
			ficBytes = make([]byte, 96)
		}

		_, err := detiReader.Read(ficBytes)
		if err != nil {
			return
		}

		for i := 0; i < len(ficBytes)/32; i++ {
			fibSlice := ficBytes[i*32 : i*32+32]
			ParseFib(fibSlice)
		}
	}
}

/* FIC */
type FigType uint8
const (
	FIG_TYPE_0 FigType = 0
	FIG_TYPE_1 FigType = 1
)

type FigExtension uint8
const (
	//FIG 00 Extension 00 - Ensemble information
	ENSEMBLE_INFORMATION FigExtension = 0
	//FIG 00 Extension 01 - Basic sub-channel organization
	BASIC_SUBCHANNEL_ORGANIZATION FigExtension = 1
	//FIG 00 Extension 02 - Basic service and service component definition
	BASIC_SERVICE_COMPONENT_DEFINITION FigExtension = 2
	//FIG 00 Extension 03 - Service component in packet mode with or without Conditional Access
	SERVICE_COMPONENT_PACKET_MODE FigExtension = 3
	//FIG 00 Extension 04 - Service component with Conditional Access in stream mode
	SERVICE_COMPONENT_STREAM_CA FigExtension = 4
	//FIG 00 Extension 05 - Service component language
	SERVICE_COMPONENT_LANGUAGE FigExtension = 5
	//FIG 00 Extension 06 - Service linking information
	SERVICE_LINKING_INFORMATION FigExtension = 6
	//FIG 00 Extension 07 - Configuration information
	CONFIGURATION_INFORMATION FigExtension = 7
	//FIG 00 Extension 08 - Service component global definition
	SERVICE_COMPONENT_GLOBAL_DEFINITION FigExtension = 8
	//FIG 00 Extension 09 - Country, LTO and International table
	COUNTRY_LTO_INTERNATIONAL_TABLE FigExtension = 9
	//FIG 00 Extension 10 - Date and time (d&t)
	DATE_AND_TIME FigExtension = 10
	//FIG 00 Extension 13 - User application information
	USERAPPLICATION_INFORMATION FigExtension = 13
	//FIG 00 Extension 14 - FEC sub-channel organization
	FEC_SUBCHANNEL_ORGANIZATION FigExtension = 14
	//FIG 00 Extension 17 - Programme Type
	PROGRAMME_TYPE FigExtension = 17
	//FIG 00 Extension 18 - Announcement support
	ANNOUNCEMENT_SUPPORT FigExtension = 18
	//FIG 00 Extension 19 - Announcement switching
	ANNOUNCEMENT_SWITCHING FigExtension = 19
	//FIG 00 Extension 20 - Service Component Information
	SERVICE_COMPONENT_INFORMATION FigExtension = 20
	//FIG 00 Extension 21 - Frequency Information
	FREQUENCY_INFORMATION FigExtension = 21
	//FIG 00 Extension 24 - OE Services
	OE_SERVICES FigExtension = 24
	//FIG 00 Extension 25 - OE Announcement support
	OE_ANNOUNCEMENT_SUPPORT FigExtension = 25
	//FIG 00 Extension 26 - OE Announcement switching
	OE_ANNOUNCEMENT_SWITCHING FigExtension = 26

	//FIG 01/02 Extension 00 - Ensemble label
	ENSEMBLE_LABEL FigExtension = 0
	//FIG 01/02 Extension 01 - Programme service label
	PROGRAMME_SERVICE_LABEL FigExtension = 1
	//FIG 01/02 Extension 04 - Service component label
	SERVICE_COMPONENT_LABEL FigExtension = 4
	//FIG 01/02 Extension 05 - Data service label
	DATA_SERVICE_LABEL FigExtension = 5
	//FIG 01/02 Extension 06 - X-PAD user application label
	XPAD_USERAPPLICATION_LABEL FigExtension = 6
)

type TransportMechanism uint8
const (
	MSC_STREAM_MODE_AUDIO	TransportMechanism = 0
	MSC_STREAM_MODE_DATA	TransportMechanism = 1
	MSC_TMID_MODE_UNKNOWN 	TransportMechanism = 2
	MSC_PACKET_MODE_DATA	TransportMechanism = 3
)

var (
	//map[subchannelId] DabSrvSubchannel
	mSubchannels map[uint8] *DabSrvSubchannel = make(map[uint8] *DabSrvSubchannel)
	mSubchannelsMutex sync.RWMutex
)

//map[serviceId] map[scids]*DabSrvComponent - Maps ServiceId to a map of ServicecompnentIdWithinService to ServiceComponent pointer
var mServiceComponents map[uint32] map[uint8] *DabSrvComponent = make(map[uint32] map[uint8] *DabSrvComponent)

//map[serviceId] map[scids]*DabUserApplication
var mUserApplications map[uint32] map[uint8][]*DabUserApplication = make(map[uint32] map[uint8][]*DabUserApplication)

//map[serviceId] *DabSrv
var mDabNewServicesPtr map[uint32]*DabSrv = make(map[uint32]*DabSrv)

//First FIG08

type MscAf struct {
	afSequenceNum	uint16
	afData			[]byte
}

type DabSrvFigs struct {
	//Ensemble info
	Fig_0_00		[]byte
	writeFig0_00	bool
	//Subchannel organisation
	Fig_0_01		[]byte
	//Service component information
	Fig_0_02		[]byte
	//Service component global definition
	Fig_0_08		[]byte
	//Country, LTO and international table
	Fig_0_09		[]byte
	Fig_0_09_done	bool
	//Date and Time
	Fig_0_10		[]byte
	writeFig0_10	bool
	//User applications
	Fig_0_13		[]byte
	//Programme Type
	Fig_0_17		[]byte

	//Labels
	//Ensemble Label
	Fig_1_00		[]byte
	Fig_1_00_done	bool
	//Programme Service Label
	Fig_1_01		[]byte
	Fig_1_01_done	bool
	//Service Component Label
	Fig_1_04		[]byte
	//X-PAD user application label
	Fig_1_06		[]byte
	//Data Service Label
	Fig_1_05		[]byte
	Fig_1_05_done	bool
}

type DabSrv struct {
	//ensemble data
	EnsembleId 				uint16
	EnsembleEcc				uint8
	EnsembleLabel		 	string
	EnsembleShortLabel 		string

	//service data
	ServiceId				uint32	//this 16-bit or 32-bit field shall identify the service
	ServiceLabel			string
	ServiceShortLabel		string

	CAId					uint8	//this 3-bit field shall identify the Access Control System (ACS) used for the service

	NumSrvComponents		uint8	//this 4-bit field, coded as an unsigned binary number, shall indicate the number of service components (maximum 12 for 16-bit SIds and maximum 11 for 32-bit SIds), associated with the service
	DabServiceComponents	[]*DabSrvComponent

	IsProgramme				bool

	Figs					DabSrvFigs

	dabserviceComplete		bool

	//EDI data
	DetiFields				[]byte
	EstData					[]byte

	AfFrameOutput 			chan []byte
}

type DabSrvSubchannel struct {
	SubchannelId 		uint8	//this 6-bit field, coded as an unsigned binary number, shall identify a sub-channel.
	StartAddress		uint16	//10-bit field, coded as an unsigned binary number (in the range 0 to 863), shall address the first Capacity Unit (CU) of the sub-channel
	ProtectionLevel		uint8 	//this 2-bit field shall indicate the protection level
	SubchannelSize		uint16	//defines the number of Capacity Units occupied by the sub-channel
	SubchannelBitrate	uint16 	//the bitrate of the subchannel in kbit/s
	FecScheme			uint8	//for packet mode components ONLY. this 2-bit field shall indicate the Forward Error Correction scheme in use

	Fig_0_01			[]byte
	Fig_0_01_done		bool

	FIG_0_14			[]byte
	FIG_0_14_done		bool

	MscInput			chan MscAf
}

type DabSrvComponent struct {
	ServiceComponentId			uint16	//this 12-bit field shall uniquely identify the service component within the ensemble - Only available for PacketMode Data Services
	ServiceComponentLabel		string
	ServiceComponentShortLabel	string
	SCIDs						uint8	//(Service Component Identifier within the Service. this 4-bit field shall identify the service component within the service. The combination of the SId and the SCIdS provides a globally valid identifier for a service component
	ServiceId					uint32
	TransportModeId				TransportMechanism	//this 2-bit field shall indicate the transport mechanism used. 0 = MSC Stream Audio. 1 = MSC Stream Data. 2 = RFU. 3 = MSC Packet Mode Data.
	ASCTy 						uint8	//this 6-bit field shall indicate the type of the audio service component. The interpretation of this field shall be as defined in ETSI TS 101 756, table 2a.
	DSCTy						uint8	// this 6-bit field shall indicate the transport protocol used by the data service component. The interpretation of this field shall be as defined in ETSI TS 101 756, table 2b.
	SubChannelId				uint8	//this 6-bit field shall identify the sub-channel in which the service component is carried.
	IsPrimary					bool	//this 1-bit flag shall indicate whether the service component is the primary one. 0: not primary (secondary); 1: primary.
	IsCaProtected				bool	//this 1-bit field flag shall indicate whether access control applies to the service component. 0: no access control; 1: access control applies to the whole of the service component.
	UserApplications			[]*DabUserApplication 	//User Applications associated with this DabSrvComponent
	//Packet Mode only
	CaOrg						uint16	//this 16-bit field shall contain information about the applied Conditional Access Systems and mode
	DataGroupsUsed				bool	//this 1-bit flag shall indicate whether the Conditional Access Organization (CAOrg) field is present, or not. 0: data groups are used to transport the service component; 1: data groups are not used to transport the service component.
	PacketAddress				uint16	//this 10-bit field shall define the address of the packet in which the service component is carried.

	Subchannel					*DabSrvSubchannel

	FIG_0_02					[]byte
	FIG_0_02_done				bool
	FIG_0_08					[]byte
	FIG_0_08_done				bool

	FIG_1_04					[]byte
	FIG_1_04_done				bool

	componentComplete			bool
}

type DabUserApplication struct {
	ServiceId			uint32	//
	SCIDs				uint8	//(Service Component Identifier within the Service. this 4-bit field shall identify the service component within the service. The combination of the SId and the SCIdS provides a globally valid identifier for a service component
	UAppType			uint16	//this 11-bit field identifies the user application that shall be used to decode the data in the channel identified by SId and SCIdS. The interpretation of this field shall be as defined in ETSI TS 101 756, table 16.
	IsXpadApp			bool 	//indicates if this application is carried as X-PAD
	XpadAppType			uint8	//this 5-bit field shall specify the lowest numbered application type used to transport this user application
	XpadAppLabel		string
	XpadAppShortLabel	string
	DataGroupsUsed		bool 	//this 1-bit flag shall indicate whether MSC data groups are used to transport the user application
	DSCTy				uint8
	IsCaProtected		bool 	//indicates if this application is protected by conditional access mechanism
	CaOrg				uint16	//this 16-bit field shall contain information about the Conditional Access Systems and mode, if present
	UAppData			[]byte	//these 8-bit fields may be used to signal application specific information. The interpretation of these fields is determined by the user application identified by the User Application Type.

	FIG_0_13			[]byte
	FIG_0_13_done		bool

	FIG_1_06			[]byte
	FIG_1_06_done		bool
}

var SubchannelCodingRate = map[uint8] []uint8 {
	0 : {12, 8, 6, 4},
	1 : {27, 21, 18, 15},
}

var SubChannelSizeShortFormTable = map[uint8] [3]uint16 {
	0  : { 16, 5,  32},
	1  : { 21, 4,  32},
	2  : { 24, 3,  32},
	3  : { 29, 2,  32},
	4  : { 35, 1,  32},
	5  : { 24, 5,  48},
	6  : { 29, 4,  48},
	7  : { 35, 3,  48},
	8  : { 42, 2,  48},
	9  : { 52, 1,  48},
	10 : { 29, 5,  56},
	11 : { 35, 4,  56},
	12 : { 42, 3,  56},
	13 : { 52, 2,  56},
	14 : { 32, 5,  64},
	15 : { 42, 4,  64},
	16 : { 48, 3,  64},
	17 : { 58, 2,  64},
	18 : { 70, 1,  64},
	19 : { 40, 5,  80},
	20 : { 52, 4,  80},
	21 : { 58, 3,  80},
	22 : { 70, 2,  80},
	23 : { 84, 1,  80},
	24 : { 48, 5,  96},
	25 : { 58, 4,  96},
	26 : { 70, 3,  96},
	27 : { 84, 2,  96},
	28 : {104, 1,  96},
	29 : { 58, 5, 112},
	30 : { 70, 4, 112},
	31 : { 84, 3, 112},
	32 : {104, 2, 112},
	33 : { 64, 5, 128},
	34 : { 84, 4, 128},
	35 : { 96, 3, 128},
	36 : {116, 2, 128},
	37 : {140, 1, 128},
	38 : { 80, 5, 160},
	39 : {104, 4, 160},
	40 : {116, 3, 160},
	41 : {140, 2, 160},
	42 : {168, 1, 160},
	43 : { 96, 5, 192},
	44 : {116, 4, 192},
	45 : {140, 3, 192},
	46 : {168, 2, 192},
	47 : {208, 1, 192},
	48 : {116, 5, 224},
	49 : {140, 4, 224},
	50 : {168, 3, 224},
	51 : {208, 2, 224},
	52 : {232, 1, 224},
	53 : {128, 5, 256},
	54 : {168, 4, 256},
	55 : {192, 3, 256},
	56 : {232, 2, 256},
	57 : {280, 1, 256},
	58 : {160, 5, 320},
	59 : {208, 4, 320},
	60 : {280, 2, 320},
	61 : {192, 5, 384},
	62 : {280, 3, 384},
	63 : {416, 1, 384},
}

var mCifCntHi uint8
var mCifCntLo uint8

//TODO try callback channel
type ServicesReadyCallbackNew func(dabServices []*DabSrv)

var mServicesReadyCallbackNew ServicesReadyCallbackNew

func RegisterServicesReadyCallbackNew(callback ServicesReadyCallbackNew) {
	mServicesReadyCallbackNew = callback
}

func UnregisterServicesReadyCallbackNew(callback ServicesReadyCallbackNew) {
	mServicesReadyCallbackNew = nil
}

type ToggleCallback func(dLabel DynamicLabel)
var mToggleCallback ToggleCallback
func RegisterToggleCallback(callback ToggleCallback) {
	mToggleCallback = callback
}

type SlideshowCallback func(sls MotSlideshow)
var mSlideshowCallback SlideshowCallback
func RegisterSlideshowCallback(callback SlideshowCallback) {
	mSlideshowCallback = callback
}

var allservicesReady bool

//Parses a 32 byte Fast Information Block
func ParseFib(fibSlice []byte) {

	fibChkSum := crc16.ChecksumCCITTFalse(fibSlice[0:30])
	fibCrc := binary.BigEndian.Uint16(fibSlice[30:32]) ^ 0xFFFF

	if fibChkSum != fibCrc {
		if mVerbose { fmt.Printf("FIB CRC mismatch: 0x%04X Is: 0x%04X\n", fibChkSum, fibCrc) }
		return
	}

	fibReader := bytes.NewReader(fibSlice)
	for pos, _ := fibReader.Seek(0, os.SEEK_CUR); pos < 30; pos, _ = fibReader.Seek(0, os.SEEK_CUR) {
		typeLenByte, err := fibReader.ReadByte()
		if err != nil {
			break
		}

		figType := (FigType)(typeLenByte >> 5)
		figLength := typeLenByte & 0x1F

		//end marker
		if figType == 7 && figLength == 31 {
			break
		}

		figPayload := make([]byte, figLength)
		fibReader.Read(figPayload)

		if figType == FIG_TYPE_0 {
			//isNextConfiguration := ((figPayload[0] & 0x80) >> 7) != 0
			//isOtherEnsemble := ((figPayload[0] & 0x40) >> 6) != 0
			isDataService := ((figPayload[0] & 0x20) >> 5) != 0
			figExt := (FigExtension)(figPayload[0] & 0x1F)

			switch figExt {
			case ENSEMBLE_INFORMATION:
				ensembleId := binary.BigEndian.Uint16(figPayload[1:3])
				/*
					ChangeFlags:
						0 0 : No change, no occurence change field present
						0 1 : next sub-channel organization only signalled (legacy support only)
						1 0 : next service organization only signalled  (legacy support only)
						1 1 : complete next MCI (sub-channel organization and service organization) signalled
				*/
				changeFlag := (figPayload[3] & 0xC0) >> 6
				isAlarmSupported := ((figPayload[3] & 0x20) >> 5) != 0
				cifCntHigh := figPayload[3] & 0x1F
				cifCntLow := figPayload[4]

				var ocChange uint8
				if changeFlag > 0 {
					ocChange = figPayload[5]

					if mVerbose { fmt.Printf("################## FIG_0_EXT_%d: EnsembleId: 0x%02X OccChange at: %d, Current: %d, AlarmSupported: %t\n", figExt, ensembleId, cifCntLow, ocChange, isAlarmSupported) }
				}

				if mCifCntHi == 0xFF && mCifCntLo == 0xFF {
					if mVerbose { fmt.Printf("################## FIG_0_EXT_%d: CifCnt initial Hi: %d, Lo: %d\n", figExt, cifCntHigh, cifCntLow) }

					mCifCntHi = cifCntHigh
					mCifCntLo = cifCntLow
				} else {
					if (mCifCntLo+4)%250 == cifCntLow {
						if cifCntLow < mCifCntLo {
							mCifCntHi++
						}
					}
					if (mCifCntHi)%20 != cifCntHigh || (mCifCntLo+4)%250 != cifCntLow {
						if mVerbose { fmt.Printf("[EdiSplitter] FIG_0_EXT_%d: CifCnt interrupted Hi: %d - %d, Lo: %d - %d\n", figExt, cifCntHigh, mCifCntHi, cifCntLow, mCifCntLo) }
					}
				}

				mCifCntHi = cifCntHigh
				mCifCntLo = cifCntLow

				var ffigPayload []byte
				var typeLen byte
				typeLen |= (0 << 5)
				typeLen |= (byte)(len(figPayload))
				ffigPayload = append(ffigPayload, typeLen)
				ffigPayload = append(ffigPayload, figPayload[:]...)

				for _, dabSrvPtr := range mDabNewServicesPtr {
					dabSrvPtr.EnsembleId = ensembleId
					dabSrvPtr.Figs.Fig_0_00 = ffigPayload
					dabSrvPtr.Figs.writeFig0_00 = true
				}

			case BASIC_SUBCHANNEL_ORGANIZATION:
				fibReader := bytes.NewReader(figPayload[1:])
				for {
					var figData []byte
					figData = append(figData, 0x00)
					figData = append(figData, 0x01)

					fibByte, err := fibReader.ReadByte()
					if err != nil {
						break
					}

					figData = append(figData, fibByte)

					var subChannelId uint8 = (fibByte & 0xFC) >> 2
					var startAddress uint16 = (uint16)((fibByte & 0x03) << 8)

					fibByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					startAddress |= (uint16)(fibByte)

					figData = append(figData, fibByte)

					fibByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					figData = append(figData, fibByte)

					longForm := (fibByte >> 7) != 0

					var protectionLevel uint8 = 0xFF
					var subchannelSize uint16 = 0xFFFF
					var subchannelBitrate uint16 = 0xFFFF
					if !longForm {
						fmt.Println("FIG_01 ShortForm")
						//tableSwitch := (fibByte&0x40)>>6 != 0
						tableIndex := fibByte & 0x3F
						subchannelSize = SubChannelSizeShortFormTable[tableIndex][0]
						protectionLevel = uint8(SubChannelSizeShortFormTable[tableIndex][1])
						subchannelBitrate = SubChannelSizeShortFormTable[tableIndex][2]
					} else {
						option := (fibByte & 0x70) >> 4
						protectionLevel = (fibByte & 0x0C) >> 2

						subchannelSize = (uint16)((fibByte & 0x03) << 8)
						fibByte, err = fibReader.ReadByte()
						if err != nil {
							break
						}
						subchannelSize |= (uint16)(fibByte)

						if option == 0 {
							subchannelBitrate = subchannelSize * 8 / uint16(SubchannelCodingRate[0][protectionLevel])
						} else if option == 1 {
							subchannelBitrate = subchannelSize * 32 / uint16(SubchannelCodingRate[1][protectionLevel])
						}

						figData = append(figData, fibByte)

					}

					mSubchannelsMutex.Lock()
					if _, contains := mSubchannels[subChannelId]; !contains {
						if mVerbose { fmt.Printf("FIG_01 Adding SubchannelInformation for SubChanId: 0x%02X, StartAddress: %d, ProtectionLevel: %d, ChannelSize: %d, SubchannelBitrate: %d\n", subChannelId, startAddress, protectionLevel, subchannelSize, subchannelBitrate) }

						subchannel := new(DabSrvSubchannel)
						subchannel.SubchannelId = subChannelId
						subchannel.StartAddress = startAddress
						subchannel.ProtectionLevel = protectionLevel
						subchannel.SubchannelSize = subchannelSize
						subchannel.SubchannelBitrate = subchannelBitrate
						subchannel.MscInput = make(chan MscAf)

						var typeLen byte
						typeLen |= (0 << 5)
						typeLen |= (byte)(len(figData) - 1)
						figData[0] = typeLen

						subchannel.Fig_0_01 = figData

						mSubchannels[subChannelId] = subchannel
					}
					mSubchannelsMutex.Unlock()
				}

			case BASIC_SERVICE_COMPONENT_DEFINITION:
				fibReader := bytes.NewReader(figPayload[1:])

				for {
					var figData []byte
					figData = append(figData, 0x00)
					figData = append(figData, 0x02)

					var serviceId uint32
					if !isDataService {
						serviceIdBytes := make([]byte, 2)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							break
						}

						serviceId = (uint32)(binary.BigEndian.Uint16(serviceIdBytes))

						figData = append(figData, serviceIdBytes[0])
						figData = append(figData, serviceIdBytes[1])
					} else {
						serviceIdBytes := make([]byte, 4)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							break
						}

						serviceId = binary.BigEndian.Uint32(serviceIdBytes)

						figData = append(figData, serviceIdBytes[0])
						figData = append(figData, serviceIdBytes[1])
						figData = append(figData, serviceIdBytes[2])
						figData = append(figData, serviceIdBytes[3])
					}

					nextByte, err := fibReader.ReadByte()
					if err != nil {
						break
					}

					figData = append(figData, 0x01)

					caid := (nextByte & 0x70) >> 4
					numServiceComponents := nextByte & 0x0F

					//Create a new DabSrv if it doesn't exist already
					if _, containsDabSrv := mDabNewServicesPtr[serviceId]; !containsDabSrv {
						if mVerbose { fmt.Printf("FIG_0_EXT_%d: adding new DabSrv for ServiceId: 0x%X with %d Components\n", figExt, serviceId, numServiceComponents) }
						newSrv := new(DabSrv)

						newSrv.ServiceId = serviceId
						newSrv.NumSrvComponents = numServiceComponents
						newSrv.CAId = caid
						newSrv.IsProgramme = !isDataService
						newSrv.AfFrameOutput = make(chan []byte, 10)

						mDabNewServicesPtr[serviceId] = newSrv
					}

					//Check if the yet available servicecomponents from FIG08 matches numComponents
					var srvCompsRdy bool = false
					if len(mServiceComponents[serviceId]) == int(numServiceComponents) {
						srvCompsRdy = true
					} else {
						if mVerbose { fmt.Printf("FIG_0_EXT_%d: ServiceComponents not yet complete for ServiceId: 0x%X with %d out of %d components\n", figExt, serviceId, len(mServiceComponents[serviceId]), numServiceComponents) }
					}

					var subChannelId uint8
					for i := 0; i < (int)(numServiceComponents); i++ {
						nextByte, err := fibReader.ReadByte()
						if err != nil {
							break
						}

						transportModeId := (nextByte & 0xC0) >> 6

						var transportMechanismId TransportMechanism
						switch transportModeId {
						//MSC Stream Audio
						case 0:
							//Match between Extension 8 and 2 is made by SubchannelId
							transportMechanismId = MSC_STREAM_MODE_AUDIO

							var singleFig []byte
							if !isDataService {
								//length / type
								singleFig = []byte{0x06, 0x02}
								singleFig = append(singleFig, figData[2:4]...)
							} else {
								//length / type
								singleFig = []byte{0x08, 0x02}
								singleFig = append(singleFig, figData[2:6]...)
							}

							//NumComponents
							singleFig = append(singleFig, 0x01)

							figData = append(figData, nextByte)

							singleFig = append(singleFig, nextByte)

							audioServiceComponentType := nextByte & 0x3F

							nextByte, err := fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: Error reading next byte for %d servicecomponents\n", figExt, numServiceComponents) }
								break
							}

							figData = append(figData, nextByte)
							singleFig = append(singleFig, nextByte)

							subChannelId = (nextByte & 0xFC) >> 2
							isPrimary := ((nextByte & 0x02) >> 1) != 0
							isCaProtected := (nextByte & 0x01) != 0

							if srvCompsRdy {
								for _, compPtr := range mServiceComponents[serviceId] {
									if compPtr.SubChannelId == subChannelId && compPtr.TransportModeId == MSC_TMID_MODE_UNKNOWN {
										if mVerbose { fmt.Printf("FIG_0_EXT_%d: completing Audio ServiceComponent data for ServiceId: 0x%x and SubchannelId: 0x%02x\n", figExt, serviceId, subChannelId) }
										compPtr.TransportModeId = transportMechanismId
										compPtr.ASCTy = audioServiceComponentType
										compPtr.DSCTy = 0xFF
										compPtr.IsPrimary = isPrimary
										compPtr.IsCaProtected = isCaProtected
										//FIG for this single servicecomponent
										compPtr.FIG_0_02 = singleFig
										if mVerbose { fmt.Printf("FIG_0_EXT_%d: SingleFig: 0x%X\n", figExt, singleFig) }

										linkSub := mSubchannels[compPtr.SubChannelId]
										//link the Subchannel to this servicecomponent
										compPtr.Subchannel = linkSub
										compPtr.componentComplete = true
										if mVerbose { fmt.Printf("Starting SrvCompRead for: 0x%02X\n", compPtr.Subchannel.SubchannelId) }
									}
								}
							}

						//MSC Stream Data
						case 1:
							//Match between Extension 8 and 2 is made by SubchannelId
							transportMechanismId = MSC_STREAM_MODE_DATA

							var singleFig []byte
							if !isDataService {
								//length / type
								singleFig = []byte{0x06, 0x02}
								singleFig = append(singleFig, figData[2:4]...)
							} else {
								//length / type
								singleFig = []byte{0x08, 0x02}
								singleFig = append(singleFig, figData[2:6]...)
							}

							//NumComponents
							singleFig = append(singleFig, 0x01)

							figData = append(figData, nextByte)

							singleFig = append(singleFig,nextByte)

							serviceComponentType := nextByte & 0x3F

							nextByte, err := fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: Error reading next byte for %d servicecomponents\n", figExt, numServiceComponents) }
								break
							}

							figData = append(figData, nextByte)
							singleFig = append(singleFig,nextByte)

							subChannelId = (nextByte & 0xFC) >> 2
							isPrimary := ((nextByte & 0x02) >> 1) != 0
							isCaProtected := (nextByte & 0x01) != 0

							if srvCompsRdy {
								for _, compPtr := range mServiceComponents[serviceId] {
									if compPtr.SubChannelId == subChannelId && compPtr.TransportModeId == MSC_TMID_MODE_UNKNOWN {
										if mVerbose { fmt.Printf("FIG_0_EXT_%d: completing StreamData ServiceComponent data for ServiceId: 0x%x and SubchannelId: 0x%02x\n", figExt, serviceId, subChannelId) }
										compPtr.TransportModeId = transportMechanismId
										compPtr.ASCTy = 0xFF
										compPtr.DSCTy = serviceComponentType
										compPtr.IsPrimary = isPrimary
										compPtr.IsCaProtected = isCaProtected
										//FIG for this single servicecomponent
										compPtr.FIG_0_02 = singleFig

										if mVerbose { fmt.Printf("FIG_0_EXT_%d: SingleFig: 0x%X\n", figExt, singleFig) }

										linkSub := mSubchannels[compPtr.SubChannelId]
										//link the Subchannel to this servicecomponent
										compPtr.Subchannel = linkSub
										compPtr.componentComplete = true
										if mVerbose { fmt.Printf("Starting SrvCompRead for: 0x%02X\n", compPtr.Subchannel.SubchannelId) }
									}
								}
							}

						case 3:
							//Match between Extension 8 and 2 is made by ServiceComponentId
							transportMechanismId = MSC_PACKET_MODE_DATA

							var singleFig []byte
							if !isDataService {
								//length / type
								singleFig = []byte{0x06, 0x02}
								singleFig = append(singleFig, figData[2:4]...)
							} else {
								//length / type
								singleFig = []byte{0x08, 0x02}
								singleFig = append(singleFig, figData[2:6]...)
							}

							//NumComponents
							singleFig = append(singleFig, 0x01)

							figData = append(figData, nextByte)
							singleFig = append(singleFig,nextByte)

							serviceComponentId := uint16((nextByte & 0x3F) << 6)

							nextByte, err = fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: Error reading next byte for %d servicecomponents\n", figExt, numServiceComponents) }
								break
							}

							figData = append(figData, nextByte)
							singleFig = append(singleFig,nextByte)

							serviceComponentId |= uint16((nextByte & 0xFC) >> 2)

							isPrimary := ((nextByte & 0x02) >> 1) != 0
							isCaProtected := (nextByte & 0x01) != 0

							if srvCompsRdy {
								for _, compPtr := range mServiceComponents[serviceId] {
									if compPtr.ServiceComponentId == serviceComponentId && compPtr.TransportModeId == MSC_TMID_MODE_UNKNOWN && compPtr.SubChannelId != 0xFF {
										if mVerbose { fmt.Printf("FIG_0_EXT_%d: completing PacketData ServiceComponent data for ServiceId: 0x%x and SubchannelId: 0x%02x\n", figExt, serviceId, subChannelId) }
										compPtr.TransportModeId = transportMechanismId
										compPtr.IsPrimary = isPrimary
										compPtr.IsCaProtected = isCaProtected
										//FIG for this single servicecomponent
										compPtr.FIG_0_02 = singleFig

										if mVerbose { fmt.Printf("FIG_0_EXT_%d: SingleFig: 0x%X\n", figExt, singleFig) }

										compPtr.componentComplete = true
										if mVerbose { fmt.Printf("Starting SrvCompRead for: 0x%02X\n", compPtr.Subchannel.SubchannelId) }
									}
								}
							}
						}
					}

					if srvCompsRdy {
						if !mDabNewServicesPtr[serviceId].dabserviceComplete {
							var typeLen byte
							typeLen |= (0 << 5)
							typeLen |= (byte)(len(figData) - 1)
							figData[0] = typeLen
							if !isDataService {
								figData[4] = (figData[4] & 0xF0) | numServiceComponents
							} else {
								figData[6] = (figData[6] & 0xF0) | numServiceComponents
							}

							mDabNewServicesPtr[serviceId].Figs.Fig_0_02 = figData
						}
					}
				}

			case SERVICE_COMPONENT_PACKET_MODE:
				fibReader := bytes.NewReader(figPayload[1:])

				for {
					nextByte, err := fibReader.ReadByte()
					if err != nil {
						break
					}

					scid := uint16(nextByte) << 4

					nextByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					scid |= uint16((nextByte & 0xF0) >> 4)

					caOrgFieldPresent := nextByte & 0x01 != 0

					nextByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					dataGroupsUsed := nextByte & 0x80 == 0
					dscty := nextByte & 0x3F

					nextByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					subChanId := (nextByte & 0xFC) >> 2
					packetAddress := uint16((nextByte & 0x03) << 8)

					nextByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					packetAddress |= uint16(nextByte)

					var caOrgField uint16 = 0x00
					if caOrgFieldPresent {
						nextByte, err = fibReader.ReadByte()
						if err != nil {
							break
						}

						caOrgField = uint16(nextByte << 8)

						nextByte, err = fibReader.ReadByte()
						if err != nil {
							break
						}

						caOrgField |= uint16(nextByte)
					}

					for _, srvCompPtrArr := range mServiceComponents {
						for _, srvCompPtr := range srvCompPtrArr {
							if srvCompPtr.ServiceComponentId == scid && srvCompPtr.SubChannelId == 0xFF {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: updating ServiceComponent with ScId: 0x%0X with SubChanId: 0x%02X at PacketAddress: 0x%04X\n", figExt, scid, subChanId, packetAddress) }
								srvCompPtr.SubChannelId = subChanId
								srvCompPtr.DataGroupsUsed = dataGroupsUsed
								srvCompPtr.DSCTy = dscty
								srvCompPtr.ASCTy = 0xFF
								srvCompPtr.PacketAddress = packetAddress

								subchan := mSubchannels[subChanId]
								srvCompPtr.Subchannel = subchan
							}
						}
					}
				}

			case SERVICE_COMPONENT_GLOBAL_DEFINITION:
				fibReader := bytes.NewReader(figPayload[1:])

				for {
					var figData []byte
					figData = append(figData, 0x00)
					figData = append(figData, 0x08)

					var serviceId uint32
					if !isDataService {
						serviceIdBytes := make([]byte, 2)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							break
						}

						serviceId = (uint32)(binary.BigEndian.Uint16(serviceIdBytes))
						figData = append(figData, serviceIdBytes[:]...)
					} else {
						serviceIdBytes := make([]byte, 4)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							break
						}

						serviceId = binary.BigEndian.Uint32(serviceIdBytes)
						figData = append(figData, serviceIdBytes[:]...)
					}

					nextByte, err := fibReader.ReadByte()
					if err != nil {
						break
					}

					extFLag := ((nextByte & 0x80) >> 7) != 0
					//3 bits RFA
					scids := nextByte & 0x0F

					figData = append(figData, nextByte)

					nextByte, err = fibReader.ReadByte()
					if err != nil {
						break
					}

					shortForm := ((nextByte & 0x80) >> 7) == 0
					var subChannelId uint8 = 0xFF
					var scid uint16 = 0xFFFF
					figData = append(figData, nextByte)
					if !shortForm {
						scid = 0x00
						scid |= uint16((nextByte & 0x0F) << 8)
						nextByte, err = fibReader.ReadByte()
						if err != nil {
							break
						}

						scid |= uint16(nextByte & 0xFF)
						figData = append(figData, nextByte)
					} else {
						subChannelId = nextByte & 0x3F
					}

					if extFLag {
						nextByte, err = fibReader.ReadByte()
						if err != nil {
							break
						}

						figData = append(figData, nextByte)
					}

					if _, srvExists := mDabNewServicesPtr[serviceId]; !srvExists {
						if mVerbose { fmt.Printf("FIG_0_EXT_%d: Waiting for DabSrv 0x%08X assembly before adding components\n", figExt, serviceId) }
						break
					}

					if _, containsSrvId := mServiceComponents[serviceId]; !containsSrvId {
						newComponentPtr := new(DabSrvComponent)
						newComponentPtr.ServiceComponentId = scid
						newComponentPtr.SCIDs = scids
						newComponentPtr.ServiceId = serviceId
						newComponentPtr.SubChannelId = subChannelId
						newComponentPtr.TransportModeId = MSC_TMID_MODE_UNKNOWN

						var typeLen byte
						typeLen |= 0 << 5
						typeLen |= (byte)(len(figData) - 1)
						figData[0] = typeLen
						newComponentPtr.FIG_0_08 = figData

						if mVerbose { fmt.Printf("FIG_0_EXT_%d: Adding new ServiceComponentMap for ServiceId: 0x%X with SCIDs: 0x%X and SubchannelId: 0x%X, FigData: 0x%X\n", figExt, serviceId, scids, subChannelId, figData) }

						newMap := map[uint8]*DabSrvComponent{scids : newComponentPtr}
						mServiceComponents[serviceId] = newMap

						mDabNewServicesPtr[serviceId].DabServiceComponents = append(mDabNewServicesPtr[serviceId].DabServiceComponents, newComponentPtr)
					} else {
						if _, containsScids := mServiceComponents[serviceId][scids]; !containsScids {
							newComponentPtr := new(DabSrvComponent)
							newComponentPtr.ServiceComponentId = scid
							newComponentPtr.SCIDs = scids
							newComponentPtr.ServiceId = serviceId
							newComponentPtr.SubChannelId = subChannelId
							newComponentPtr.TransportModeId = MSC_TMID_MODE_UNKNOWN

							var typeLen byte
							typeLen |= 0 << 5
							typeLen |= (byte)(len(figData) - 1)
							figData[0] = typeLen
							newComponentPtr.FIG_0_08 = figData

							if mVerbose { fmt.Printf("FIG_0_EXT_%d: Adding new ServiceComponent to existing Map for ServiceId: 0x%X with SCIDs: 0x%X and SubchannelId: 0x%X, FigData: 0x%X\n", figExt, serviceId, scids, subChannelId, figData) }

							mServiceComponents[serviceId][scids] = newComponentPtr

							mDabNewServicesPtr[serviceId].DabServiceComponents = append(mDabNewServicesPtr[serviceId].DabServiceComponents, newComponentPtr)
						}
					}
				}

			case COUNTRY_LTO_INTERNATIONAL_TABLE:
				//fmt.Printf("COUNTRY_LTO_INTERNATIONAL_TABLE\n")

				ensembleEcc := figPayload[2]
				for _, dabSrvPtr := range mDabNewServicesPtr {
					dabSrvPtr.EnsembleEcc = ensembleEcc
				}

				var ffigPayload []byte
				var typeLen byte
				typeLen |= 0 << 5
				typeLen |= (byte)(len(figPayload))
				ffigPayload = append(ffigPayload, typeLen)
				ffigPayload = append(ffigPayload, figPayload[:]...)

				for _, dabSrvPtr := range mDabNewServicesPtr {
					dabSrvPtr.Figs.Fig_0_09 = ffigPayload
				}

			case DATE_AND_TIME:
				/*
				mjd := int(figPayload[1] & 0x7F) << 10 | int(figPayload[2]) << 2 | int(figPayload[3] & 0xC0) >> 6

				year, month, day := MjdToYMD(mjd)
				//fmt.Printf("FIG_0_EXT_%d: MJD: 0x%04X - %d - %d - %d\n", figExt, mjd, year, month, day)

				//LSI (Leap Second Indicator): this 1-bit flag shall be set to "1" for the period of one hour before the occurrence of a leap second.
				lsiFlag := (figPayload[3] & 0x20) >> 5 != 0
				utcFlag := (figPayload[3] & 0x08) >> 3 != 0

				hours := (figPayload[3] & 0x07) << 2 | figPayload[4] >> 6
				minutes := figPayload[4] & 0x3F
				seconds := uint8(0)
				milliSeconds := uint16(0)
				if utcFlag {
					seconds = (figPayload[5] & 0xFC) >> 2
					milliSeconds = uint16(figPayload[5] & 0x03) << 8 | uint16(figPayload[6])
				}
				goDate := time.Date(year, time.Month(month), day, int(hours), int(minutes), int(seconds), int(milliSeconds)*int(1000000), time.UTC)
				fmt.Printf("FIG_0_EXT_%d: H: %02d, M: %02d, S: %02d, MS: %03d - LSI: %t - %s - %d\n", figExt, hours, minutes, seconds, milliSeconds, lsiFlag, goDate, goDate.UnixNano())
				*/

				var ffigPayload []byte
				var typeLen byte
				typeLen |= (0 << 5)
				typeLen |= (byte)(len(figPayload))
				ffigPayload = append(ffigPayload, typeLen)
				ffigPayload = append(ffigPayload, figPayload[:]...)

				for _, dabSrvPtr := range mDabNewServicesPtr {
					dabSrvPtr.Figs.Fig_0_10 = ffigPayload
					dabSrvPtr.Figs.writeFig0_10 = true
				}

			case USERAPPLICATION_INFORMATION:
				fibReader := bytes.NewReader(figPayload[1:])

				for {
					var figData []byte
					figData = append(figData, 0x00)
					figData = append(figData, 0x0D)

					var serviceId uint32
					var serviceIdBytes []byte
					if !isDataService {
						serviceIdBytes = make([]byte, 2)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 1\n", figExt) }
							break
						}

						figData = append(figData, serviceIdBytes[:]...)

						serviceId = (uint32)(binary.BigEndian.Uint16(serviceIdBytes))
					} else {
						serviceIdBytes = make([]byte, 4)
						_, err := fibReader.Read(serviceIdBytes)
						if err != nil {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 2\n", figExt) }
							break
						}

						figData = append(figData, serviceIdBytes[:]...)
						serviceId = binary.BigEndian.Uint32(serviceIdBytes)
					}

					nextByte, err := fibReader.ReadByte()
					if err != nil {
						if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 3\n", figExt) }
						break
					}

					figData = append(figData, nextByte)

					scIds := (nextByte & 0xF0) >> 4
					numberUserApps := nextByte & 0x0F

					uappsMissing := false
					if len(mUserApplications[serviceId][scIds]) < int(numberUserApps) {
						if mUserApplications[serviceId] == nil {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: creating list for ServiceId 0x%X and SCIDs: 0x%02X\n", figExt, serviceId, scIds) }
							mUserApplications[serviceId] = make(map[uint8][]*DabUserApplication)
						}
						uappsMissing = true
					}

					if _, exists := mServiceComponents[serviceId][scIds]; !exists {
						if mVerbose { fmt.Printf("FIG_0_EXT_%d: Waiting for ServiceComponent assembly for ServiceId: 0x%04X and SCIDs: 0x%02X - 0x%02X\n", figExt, serviceId, scIds, figPayload[1:]) }
						break
					}

					for i := uint8(0); i < numberUserApps; i++ {
						next2Bytes := make([]byte, 2)
						_, err = fibReader.Read(next2Bytes)
						if err != nil {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 4\n", figExt) }
							break
						}

						singlFig13 := []byte{0x00, 0x0D}
						singlFig13 = append(singlFig13, serviceIdBytes...)
						scidsNumUapps := scIds << 4 | 0x01
						singlFig13 = append(singlFig13, scidsNumUapps)
						singlFig13 = append(singlFig13, next2Bytes...)

						var xpadAppType uint8 = 0xFF
						var isUserAppCaProt bool
						var isDataGroupsUsed bool
						var dataServiceComponentType uint8
						var caOrganization uint16
						var uappData []uint8

						figData = append(figData, next2Bytes[:]...)

						userAppType := uint16(next2Bytes[0]) << 3 | uint16(next2Bytes[1]) & 0xE0 >> 5
						userAppDataLen := next2Bytes[1] & 0x1F
						isXpadData := !isDataService

						if uappsMissing {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: ServiceId: 0x%08X and SCIDs: 0x%02X UAppType: 0x%04X, UAppDataLen: %d, isXpad: %t\n", figExt, serviceId, scIds, userAppType, userAppDataLen, isXpadData) }
						}

						if isXpadData {
							nextByte, err := fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 5\n", figExt) }
								break
							}

							figData = append(figData, nextByte)
							singlFig13 = append(singlFig13, nextByte)

							isUserAppCaProt = nextByte>>7 != 0
							caOrgFlag := ((nextByte & 0x40) >> 6) != 0
							xpadAppType = nextByte & 0x1F

							nextByte, err = fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 6\n", figExt) }
								break
							}

							figData = append(figData, nextByte)
							singlFig13 = append(singlFig13, nextByte)

							isDataGroupsUsed = nextByte>>7 != 0
							dataServiceComponentType = nextByte & 0x3F

							if caOrgFlag {
								_, err = fibReader.Read(next2Bytes)
								if err != nil {
									if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 7\n", figExt) }
									break
								}

								figData = append(figData, next2Bytes[:]...)
								singlFig13 = append(singlFig13, next2Bytes...)

								caOrganization = binary.BigEndian.Uint16(next2Bytes)
								userAppDataLen -= 2
							}

							userAppDataLen -= 2
						}

						//UserApp specific data
						for j := uint8(0); j < userAppDataLen; j++ {
							nextByte, err = fibReader.ReadByte()
							if err != nil {
								if mVerbose { fmt.Printf("FIG_0_EXT_%d: error 8\n", figExt) }
								break
							}

							uappData = append(uappData, nextByte)

							figData = append(figData, nextByte)
							singlFig13 = append(singlFig13, nextByte)
						}

						if uappsMissing {
							if mVerbose { fmt.Printf("\n") }
							newApp := new(DabUserApplication)
							newApp.IsCaProtected = isUserAppCaProt
							newApp.DataGroupsUsed = isDataGroupsUsed
							newApp.ServiceId = serviceId
							newApp.IsXpadApp = isXpadData
							newApp.UAppType = userAppType
							newApp.XpadAppType = xpadAppType
							newApp.DSCTy = dataServiceComponentType
							newApp.CaOrg = caOrganization
							newApp.UAppData = uappData

							var singleTypeLen byte
							singleTypeLen |= (byte)(len(singlFig13) - 1)
							singlFig13[0] = singleTypeLen

							newApp.FIG_0_13 = singlFig13

							mUserApplications[serviceId][scIds] = append(mUserApplications[serviceId][scIds], newApp)

							mServiceComponents[serviceId][scIds].UserApplications = append(mServiceComponents[serviceId][scIds].UserApplications, newApp)

							if mVerbose { fmt.Printf("FIG_0_EXT_%d: 0x%02X\n", figExt, figPayload[1:]) }
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: Adding UserApp for SId: 0x%04X, SCIDs: 0x%02X - ListLen: %d - 0x%02X\n", figExt, serviceId, scIds, len(mUserApplications[serviceId][scIds]), singlFig13) }
						}
					}

					if compPtr, _ := mServiceComponents[serviceId][scIds]; compPtr != nil {
						var typeLen byte
						typeLen |= 0 << 5
						typeLen |= (byte)(len(figData) - 1)
						figData[0] = typeLen
					}

					if fibReader.Len() == 0 {
						break
					}
				}

			case FEC_SUBCHANNEL_ORGANIZATION:
				fibReader := bytes.NewReader(figPayload[1:])

				for {
					var figData []byte
					figData = append(figData, 0x00)
					figData = append(figData, 0x0E)

					fibByte, err := fibReader.ReadByte()
					if err != nil {
						break
					}

					figData = append(figData, fibByte)

					var subChannelId uint8 = (fibByte & 0xFC) >> 2

					var typeLen byte
					typeLen |= 0 << 5
					typeLen |= (byte)(len(figData) - 1)
					figData[0] = typeLen

					if subchanPtr := mSubchannels[subChannelId]; subchanPtr != nil {
						if subchanPtr.FIG_0_14 == nil {
							if mVerbose { fmt.Printf("FIG_0_EXT_%d: SCID: 0x%X FEC Data: 0x%X\n", figExt, subChannelId, figData) }
							subchanPtr.FIG_0_14 = figData
						}
					}
				}
			}
		}

		if figType == FIG_TYPE_1 {
			figExt := (FigExtension)(figPayload[0] & 0x07)
			//isOtherEnsemble := ((figPayload[0] & 0x08) >> 3) != 0
			var charset uint8 = figPayload[0] & 0xF0 >> 4

			switch figExt {
			case ENSEMBLE_LABEL:
				ensembleLabel, ensembleShortLabel := parseLabels(figPayload[3:21], charset)

				for _, dabSrvPtr := range mDabNewServicesPtr {
					if len(dabSrvPtr.EnsembleLabel) == 0 {
						var ffigPayload []byte
						var typeLen byte
						typeLen |= 1 << 5
						typeLen |= (byte)(len(figPayload))
						ffigPayload = append(ffigPayload, typeLen)
						ffigPayload = append(ffigPayload, figPayload[:]...)

						dabSrvPtr.Figs.Fig_1_00 = ffigPayload

						dabSrvPtr.EnsembleLabel = ensembleLabel
						dabSrvPtr.EnsembleShortLabel = ensembleShortLabel
					}
				}

			case PROGRAMME_SERVICE_LABEL:
				serviceId := (uint32)(binary.BigEndian.Uint16(figPayload[1:3]))
				serviceLabel, serviceShortLabel := parseLabels(figPayload[3:21], charset)

				if srvPtr, exists := mDabNewServicesPtr[serviceId]; exists {

					allOkay := true
					if len(srvPtr.DabServiceComponents) > 0 {
						for _, srvComp := range srvPtr.DabServiceComponents {
							if !srvComp.componentComplete {
								if mVerbose { fmt.Printf("FIG_1_EXT_%d: waiting for Service: 0x%08X to complete ComponentId: 0x%04X, SubchannelID: 0x%02X\n", figExt, serviceId, srvComp.ServiceComponentId, srvComp.SubChannelId) }
								allOkay = false
								break
							}
						}
					} else {
						allOkay = false
					}

					if allOkay {
						if len(srvPtr.ServiceLabel) == 0 {
							if mVerbose { fmt.Printf("FIG_1_EXT_%d: Label ProgrammeSrv for 0x%08X - Label: %s - %s\n", figExt, serviceId, serviceLabel, serviceShortLabel) }
							srvPtr.ServiceLabel = serviceLabel
							srvPtr.ServiceShortLabel = serviceShortLabel

							var ffigPayload []byte
							var typeLen byte
							typeLen |= (1 << 5)
							typeLen |= (byte)(len(figPayload))
							ffigPayload = append(ffigPayload, typeLen)
							ffigPayload = append(ffigPayload, figPayload[:]...)
							srvPtr.Figs.Fig_1_01 = ffigPayload

							if mVerbose { fmt.Printf("FIG_1_EXT_%d: SrvFin SId: 0x%08X - %s, NumComps: %d\n", figExt, mDabNewServicesPtr[serviceId].ServiceId, mDabNewServicesPtr[serviceId].ServiceLabel, mDabNewServicesPtr[serviceId].NumSrvComponents) }
							for _, dabServiceComp := range mDabNewServicesPtr[serviceId].DabServiceComponents {
								if dabServiceComp.Subchannel != nil {
									if mVerbose { fmt.Printf("FIG_1_EXT_%d: SrvFin Comp SCIDs 0x%02X, SubchannelId: 0x%02X\n", figExt, dabServiceComp.SCIDs, dabServiceComp.Subchannel.SubchannelId) }
									for _, compUapp := range dabServiceComp.UserApplications {
										if mVerbose { fmt.Printf("FIG_1_EXT_%d: SrvFin UApp Type: 0x%03X\n", figExt, compUapp.UAppType) }
									}
								}
							}

							srvPtr.dabserviceComplete = true

							go readServiceData(mDabNewServicesPtr[serviceId])
						}
					}
				}

			case SERVICE_COMPONENT_LABEL:
				var isProgrammeService bool = ((figPayload[1] & 0x80) >> 7) == 0

				scids := figPayload[1] & 0x0F
				var serviceLabel string
				var serviceShortLabel string
				var serviceId uint32
				if isProgrammeService {
					serviceId = (uint32)(binary.BigEndian.Uint16(figPayload[2:4]))
					serviceLabel, serviceShortLabel = parseLabels(figPayload[4:22], charset)
				} else {
					serviceId = binary.BigEndian.Uint32(figPayload[2:6])
					serviceLabel, serviceShortLabel = parseLabels(figPayload[6:24], charset)
				}

				if _, exists := mServiceComponents[serviceId][scids]; exists {
					if len(mServiceComponents[serviceId][scids].ServiceComponentLabel) == 0 {
						if mVerbose { fmt.Printf("FIG_1_EXT_%d: Label SrvComponent for 0x%08X - 0x%02X - Label: %s - %s\n", figExt, serviceId, scids, serviceLabel, serviceShortLabel) }
						mServiceComponents[serviceId][scids].ServiceComponentLabel = serviceLabel
						mServiceComponents[serviceId][scids].ServiceComponentShortLabel = serviceShortLabel

						var ffigPayload []byte
						var typeLen byte
						typeLen |= (1 << 5)
						typeLen |= (byte)(len(figPayload))
						ffigPayload = append(ffigPayload, typeLen)
						ffigPayload = append(ffigPayload, figPayload[:]...)

						mServiceComponents[serviceId][scids].FIG_1_04 = ffigPayload
					}
				}

			case XPAD_USERAPPLICATION_LABEL:
				var isProgrammeService bool = ((figPayload[1] & 0x80) >> 7) == 0

				scids := figPayload[1] & 0x0F
				var serviceLabel string
				var serviceShortLabel string
				var serviceId uint32
				var xpadAppType uint8

				//if isProgrammeService {
				if isProgrammeService {
					serviceId = (uint32)(binary.BigEndian.Uint16(figPayload[2:4]))
					serviceLabel, serviceShortLabel = parseLabels(figPayload[5:23], charset)
					xpadAppType = figPayload[4] & 0x1F
				} else {
					serviceId = binary.BigEndian.Uint32(figPayload[2:6])
					serviceLabel, serviceShortLabel = parseLabels(figPayload[7:25], charset)
					xpadAppType = figPayload[6] & 0x1F
				}

				if _, exists := mUserApplications[serviceId][scids]; exists {
					for _, uapp := range mUserApplications[serviceId][scids] {
						if uapp.XpadAppType == xpadAppType {
							if len(uapp.XpadAppLabel) == 0 {
								if mVerbose { fmt.Printf("FIG_1_EXT_%d: Label XPAD for 0x%08X - 0x%02X - 0x%02X - Label: %s - %s\n", figExt, serviceId, scids, xpadAppType, serviceLabel, serviceShortLabel) }
								uapp.XpadAppLabel = serviceLabel
								uapp.XpadAppShortLabel = serviceShortLabel

								var ffigPayload []byte
								var typeLen byte
								typeLen |= (1 << 5)
								typeLen |= (byte)(len(figPayload))
								ffigPayload = append(ffigPayload, typeLen)
								ffigPayload = append(ffigPayload, figPayload[:]...)

								uapp.FIG_1_06 = ffigPayload
							}

							break
						}
					}
				}

			case DATA_SERVICE_LABEL:
				serviceId := binary.BigEndian.Uint32(figPayload[1:5])
				serviceLabel, serviceShortLabel := parseLabels(figPayload[5:23], charset)

				if srvPtr, exists := mDabNewServicesPtr[serviceId]; exists {
					allOkay := true
					if len(srvPtr.DabServiceComponents) > 0 {
						for _, srvComp := range srvPtr.DabServiceComponents {
							if !srvComp.componentComplete {
								if mVerbose { fmt.Printf("FIG_1_EXT_%d: waiting for Service: 0x%08X to complete ComponentId: 0x%04X, SubchannelID: 0x%02X\n", figExt, serviceId, srvComp.ServiceComponentId, srvComp.SubChannelId) }
								allOkay = false
								break
							}
						}
					} else {
						allOkay = false
					}

					if allOkay {
						if len(mDabNewServicesPtr[serviceId].ServiceLabel) == 0 {
							if mVerbose { fmt.Printf("Label DataService  for 0x%08X - Label: %s - %s\n", serviceId, serviceLabel, serviceShortLabel) }
							mDabNewServicesPtr[serviceId].ServiceLabel = serviceLabel
							mDabNewServicesPtr[serviceId].ServiceShortLabel = serviceShortLabel

							var ffigPayload []byte
							var typeLen byte
							typeLen |= (1 << 5)
							typeLen |= (byte)(len(figPayload))
							ffigPayload = append(ffigPayload, typeLen)
							ffigPayload = append(ffigPayload, figPayload[:]...)
							mDabNewServicesPtr[serviceId].Figs.Fig_1_05 = ffigPayload

							mDabNewServicesPtr[serviceId].dabserviceComplete = true

							go readServiceData(mDabNewServicesPtr[serviceId])
						}
					}
				}
			}
		}

		for _, dabSrvPtr := range mDabNewServicesPtr {
			if !dabSrvPtr.dabserviceComplete {
				if mVerbose { fmt.Printf("DABService 0x%08X is not yet complete\n", dabSrvPtr.ServiceId) }
				allDabSrvComplete = false
				break
			} else {
				allDabSrvComplete = true
			}
		}

		if allDabSrvComplete {
			if mServicesReadyCallbackNew != nil {
				srvList := make([]*DabSrv, 0, len(mDabNewServicesPtr))
				for _, srvPtr := range mDabNewServicesPtr {
					srvList = append(srvList, srvPtr)
				}

				mServicesReadyCallbackNew(srvList)
			}
		}
	}
}

func MjdToYMD(mjd int) (year int, month int, day int) {
	j := mjd + 2400001 + 68569
	c := 4 * j / 146097
	j = j - (146097 * c + 3) / 4
	y := 4000 * (j + 1) / 1461001
	j = j - 1461 * y / 4 + 31
	M := 80 * j / 2447
	day = j - 2447 * M / 80
	j = M / 11
	month = M + 2 - (12 * j)
	year = 100 * (c - 49) + y + j

	return
}

func convertToEbuLatin(labelData []byte, charset uint8) (textData string) {
	if charset == 0{
		var ebuString strings.Builder
		for _, char := range labelData {
			ebuString.WriteString(EBU_CHARSET[(char >> 4) & 0x0F][char & 0x0F])
		}

		textData = ebuString.String()
	} else {
		textData = string(labelData)
	}

	return
}

func parseLabels(labelData []byte, charset uint8) (label string, short string) {
	if charset == 0{
		var ebuString strings.Builder
		for _, char := range labelData[:16] {
			ebuString.WriteString(EBU_CHARSET[(char >> 4) & 0x0F][char & 0x0F])
		}

		label = ebuString.String()
	} else {
		label = string(labelData[:16])
	}
	shortLabel := make([]byte, 8)
	shortCnt := 0
	var i uint
	for i = 0; i < 2; i++ {
		labelByte := labelData[16+i : 17+i]
		var j uint
		for j = 0; j < 7; j++ {
			if shortCnt > 7 {
				break
			}

			if (labelByte[0]<<j)>>7 != 0 {
				shortLabel[shortCnt] = label[j+i*7]
				shortCnt++
			}
		}
	}

	short = string(shortLabel[:])
	return
}

var EBU_CHARSET = [16][16]string {
	//           -0        -1        -2        -3        -4        -5        -6        -7        -8        -9        -A        -B        -C        -D        -E        -F
	/* 0- */ {"\u0000", "\u0118", "\u012E", "\u0172", "\u0102", "\u0116", "\u010E", "\u0218", "\u021A", "\u010A", "\u0000", "\u0000", "\u0120", "\u0139", "\u017B", "\u0143"},
	/* 1- */ {"\u0105", "\u0119", "\u012F", "\u0173", "\u0103", "\u0117", "\u010F", "\u0219", "\u021B", "\u010B", "\u0147", "\u011A", "\u0121", "\u013A", "\u017C", "\u0000"},
	/* 2- */ {"\u0020", "\u0021", "\u0022", "\u0023", "\u0142", "\u0025", "\u0026", "\u0027", "\u0028", "\u0029", "\u002A", "\u002B", "\u002C", "\u002D", "\u002E", "\u002F"},
	/* 3- */ {"\u0030", "\u0031", "\u0032", "\u0033", "\u0034", "\u0035", "\u0036", "\u0037", "\u0038", "\u0039", "\u003A", "\u003B", "\u003C", "\u003D", "\u003E", "\u003F"},
	/* 4- */ {"\u0040", "\u0041", "\u0042", "\u0043", "\u0044", "\u0045", "\u0046", "\u0047", "\u0048", "\u0049", "\u004A", "\u004B", "\u004C", "\u004D", "\u004E", "\u004F"},
	/* 5- */ {"\u0050", "\u0051", "\u0052", "\u0053", "\u0054", "\u0055", "\u0056", "\u0057", "\u0058", "\u0059", "\u005A", "\u005B", "\u016E", "\u005D", "\u0141", "\u005F"},
	/* 6- */ {"\u0104", "\u0061", "\u0062", "\u0063", "\u0064", "\u0065", "\u0066", "\u0067", "\u0068", "\u0069", "\u006A", "\u006B", "\u006C", "\u006D", "\u006E", "\u006F"},
	/* 7- */ {"\u0070", "\u0071", "\u0072", "\u0073", "\u0074", "\u0075", "\u0076", "\u0077", "\u0078", "\u0079", "\u007A", "\u00AB", "\u016F", "\u00BB", "\u013D", "\u0126"},
	/* 8- */ {"\u00E1", "\u00E0", "\u00E9", "\u00E8", "\u00ED", "\u00EC", "\u00F3", "\u00F2", "\u00FA", "\u00F9", "\u00D1", "\u00C7", "\u015E", "\u00DF", "\u00A1", "\u0178"},
	/* 9- */ {"\u00E2", "\u00E4", "\u00EA", "\u00EB", "\u00EE", "\u00EF", "\u00F4", "\u00F6", "\u00FB", "\u00FC", "\u00F1", "\u00E7", "\u015F", "\u011F", "\u0131", "\u00FF"},
	/* A- */ {"\u0136", "\u0145", "\u00A9", "\u0122", "\u011E", "\u011B", "\u0148", "\u0151", "\u0150", "\u20AC", "\u00A3", "\u0024", "\u0100", "\u0112", "\u012A", "\u016A"},
	/* B- */ {"\u0137", "\u0146", "\u013B", "\u0123", "\u013C", "\u0130", "\u0144", "\u0171", "\u0170", "\u00BF", "\u013E", "\u00B0", "\u0101", "\u0113", "\u012B", "\u016B"},
	/* C- */ {"\u00C1", "\u00C0", "\u00C9", "\u00C8", "\u00CD", "\u00CC", "\u00D3", "\u00D2", "\u00DA", "\u00D9", "\u0158", "\u010C", "\u0160", "\u017D", "\u00D0", "\u013F"},
	/* D- */ {"\u00C2", "\u00C4", "\u00CA", "\u00CB", "\u00CE", "\u00CF", "\u00D4", "\u00D6", "\u00DB", "\u00DC", "\u0159", "\u010D", "\u0161", "\u017E", "\u0111", "\u0140"},
	/* E- */ {"\u00C3", "\u00C5", "\u00C6", "\u0152", "\u0177", "\u00DD", "\u00D5", "\u00D8", "\u00DE", "\u014A", "\u0154", "\u0106", "\u015A", "\u0179", "\u0164", "\u00F0"},
	/* F- */ {"\u00E3", "\u00E5", "\u00E6", "\u0153", "\u0175", "\u00FD", "\u00F5", "\u00F8", "\u00FE", "\u014B", "\u0155", "\u0107", "\u015B", "\u017A", "\u0165", "\u0127"},
}

type DabSuperframe struct {
	SamplingRate	int
	Channels		int
	Sbr				bool
	Ps				bool
}

var (
	MAfWrapMultiMap map[uint8]uint16 = make(map[uint8]uint16)
	MAfWrapMultiMapMutex = sync.RWMutex{}
)

//MSC Decoder
func readServiceData(service *DabSrv)  {
	var serviceComponent *DabSrvComponent
	for _, srvComp := range service.DabServiceComponents {
		if srvComp.IsPrimary {
			serviceComponent = srvComp
			break
		}
	}

	MAfWrapMultiMapMutex.Lock()
	if _, scMultiExists := MAfWrapMultiMap[serviceComponent.Subchannel.SubchannelId]; !scMultiExists {
		if mVerbose { fmt.Printf("ToggleC adding MultiplierMap for 0x%02X\n", serviceComponent.Subchannel.SubchannelId) }
		MAfWrapMultiMap[serviceComponent.Subchannel.SubchannelId] = 0
	}
	MAfWrapMultiMapMutex.Unlock()

	superFrameSize := (serviceComponent.Subchannel.SubchannelBitrate / 8) * 110
	payloadSize := serviceComponent.Subchannel.SubchannelBitrate * 3

	if mVerbose { fmt.Printf("SuperframeSize: %d, PayloadSize: %d SubchanSize: %d Bitrate: %d\n", superFrameSize, payloadSize, serviceComponent.Subchannel.SubchannelSize, serviceComponent.Subchannel.SubchannelBitrate) }

	var sfCnt = 0
	var superFrameData []byte

	//var samplingRate int
	//var channels int
	var sbr bool
	//var ps bool
	var numAUs int
	var isSync bool
	var auStarts []uint16
	//var auLengths []uint16
	for {
		mscAfData := <-serviceComponent.Subchannel.MscInput

		if mscAfData.afSequenceNum == 0xFFFF {
			MAfWrapMultiMapMutex.Lock()
			if mVerbose { fmt.Printf("ToggleC Subchan 0x%02X AF wrap from multi: %d\n", serviceComponent.Subchannel.SubchannelId, MAfWrapMultiMap[serviceComponent.Subchannel.SubchannelId]) }
			MAfWrapMultiMap[serviceComponent.Subchannel.SubchannelId]++
			MAfWrapMultiMapMutex.Unlock()
		}

		if service.IsProgramme {
			mscData := mscAfData.afData
			if sfCnt == 0 {
				if CheckFireCode(mscData) {
					//fmt.Printf("FireCode match for SubchanID: 0x%02X - %d - %d\n", serviceComponent.Subchannel.SubchannelId, superFrameSize, payloadSize)

					dacRate := ((mscData[2] & 0x40) >> 6) != 0
					//chanMode := ((mscData[2] & 0x10) >> 4) != 0
					//ps = ((mscData[2] & 0x08) >> 3) != 0
					sbr = ((mscData[2] & 0x20) >> 5) != 0

					/*TODO alignmentPresent*/ _ = !(dacRate && sbr)

					//reset old data
					superFrameData = mscData
					auStarts = nil

					/*
						if dacRate {
							samplingRate = 48000
						} else {
							samplingRate = 32000
						}
					*/

					/*
						if chanMode {
							channels = 2
						} else {
							channels = 1
						}
					*/

					if !dacRate && sbr {
						numAUs = 2
					}
					if dacRate && sbr {
						numAUs = 3
					}
					if !dacRate && !sbr {
						numAUs = 4
					}
					if dacRate && !sbr {
						numAUs = 6
					}

					switch numAUs {
					case 2:
						auStarts = append(auStarts, 5)
					case 3:
						auStarts = append(auStarts, 6)
					case 4:
						auStarts = append(auStarts, 8)
					case 6:
						auStarts = append(auStarts, 11)
					default:
						if mVerbose {
							fmt.Printf("SuperframeBuilder Bad number of AUs: %d\n", numAUs)
						}
					}

					//other AU starts

					var lastByte byte
					var byteCnt int
					var badAuStart bool
					for i := 1; i < numAUs; i++ {
						var auStart uint16
						if i%2 > 0 {
							lastByte = mscData[3+byteCnt]
							byteCnt++
							auStart |= uint16(lastByte) << 4
							lastByte = mscData[3+byteCnt]
							byteCnt++
							auStart |= uint16(lastByte) >> 4
						} else {
							auStart |= uint16(lastByte&0x0F) << 8
							lastByte = mscData[3+byteCnt]
							byteCnt++
							auStart |= uint16(lastByte)
						}

						if auStart > superFrameSize || auStart <= auStarts[i-1] {
							badAuStart = true
							break
						}

						auStarts = append(auStarts, auStart)
					}

					if badAuStart {
						if mVerbose {
							fmt.Printf("Bad AU start\n")
						}
						continue
					}

					auStarts = append(auStarts, superFrameSize)

					sfCnt++
					isSync = true

					continue
				}
			}

			if isSync {
				superFrameData = append(superFrameData, mscData...)
				sfCnt++

				if sfCnt == 5 {
					for i := 0; i < numAUs; i++ {
						if len(superFrameData) < int(auStarts[i+1]) {
							if mVerbose { fmt.Printf("Not enough SuperframeData for AU start: %d, it's only: %d\n", auStarts[i+1], len(superFrameData)) }
							break
						}

						au := superFrameData[auStarts[i]:auStarts[i+1]]
						chkSum := crc16.ChecksumCCITTFalse(au)

						if chkSum == 0x1D0F {
							if (au[0]>>5)&0x07 == 0x04 {
								padDataStart := uint8(0x02)
								padDataLen := uint8(au[1])
								if padDataLen == 0xFF {
									padDataLen += au[2]
									padDataStart++
								}

								padData := au[padDataStart : padDataStart+padDataLen]

								processPadData(padData, serviceComponent.Subchannel.SubchannelId, mscAfData.afSequenceNum)

								auStarts[i] += uint16(padDataStart) + uint16(padDataLen)
							}
						} else {
							if mVerbose {
								fmt.Printf("AU CRC Error at: %d - %d - %d\n", i, len(au), superFrameSize)
							}
						}
					}

					//reset
					sfCnt = 0
					isSync = false
				}
			}
		}
	}
}

type XPadIndicator uint8
const (
	//ENSEMBLE_INFORMATION FigExtension = 0
	No_Xpad 		XPadIndicator = 0
	Short_Xpad		XPadIndicator = 1
	Variable_Xpad	XPadIndicator = 2
	RFU_XPad		XPadIndicator = 3
)

type PadApplicationType uint8
const (
	PAD_APP_END_MARKER						PadApplicationType =  0
	PAD_APP_DATA_GROUP_LENGTH_INDICATOR		PadApplicationType =  1
	PAD_APP_DLS_DATAGROUP_START				PadApplicationType =  2
	PAD_APP_DLS_DATAGROUP_CONTINUATION		PadApplicationType =  3
	//4-11 user defined
	PAD_APP_MOT_DATAGROUP_START 			PadApplicationType = 12
	PAD_APP_MOT_DATAGROUP_CONTINUATION		PadApplicationType = 13
	PAD_APP_MOT_CA_MESSAGE_START			PadApplicationType = 14
	PAD_APP_MOT_CA_MESSAGE_CONTINUATION		PadApplicationType = 15
	//16 - 31 user defined
	PAD_APP_NOT_USED 						PadApplicationType = 31
)

var XPadSize = [8]uint8 {
	4, 6, 8, 12, 16, 24, 32, 48,
}

type parsedXpadApp struct {
	dataSubfieldLen uint8
	padAppType		PadApplicationType
}

type PadDataProcessor struct {
	subChannelId		uint8
	previousPadAppType 	PadApplicationType
	previousXpadSize 	uint8
}

var (
	mPadDataProcessors = make(map[uint8] *PadDataProcessor)
	mPadDataProcessorsMutex = sync.RWMutex{}
)

func processPadData(padData []byte, subchannelId uint8, afSeqNum uint16) {
	//Reverse PAD data slice
	for i := len(padData)/2-1; i >= 0; i-- {
		el := len(padData)-1-i
		padData[i], padData[el] = padData[el], padData[i]
	}

	mPadDataProcessorsMutex.Lock()
	if _, pdpExists := mPadDataProcessors[subchannelId]; !pdpExists {
		if mVerbose { fmt.Printf("Adding new PadDataProcessor for SubchanId: 0x%02X\n", subchannelId) }

		newPdp := new(PadDataProcessor)
		newPdp.subChannelId = subchannelId
		newPdp.previousPadAppType = 0xFF
		newPdp.previousXpadSize = 0

		mPadDataProcessors[subchannelId] = newPdp
	}

	curPdp := mPadDataProcessors[subchannelId]

	mPadDataProcessorsMutex.Unlock()

	padReader := bytes.NewReader(padData)

	for padReader.Len() > 0 {
		nextByte, readErr := padReader.ReadByte()
		if readErr != nil {
			if mVerbose { fmt.Printf("PadReader error: %s\n", readErr) }
		}

		//CI (Contents Indicator) flag: this 1-bit flag shall signal whether the X-PAD field in the current DAB audio frame includes at least one contents indicator. 0: no contents indicator; 1: contents indicator(s) present.
		ciPresent := (nextByte & 0x02) >> 1 != 0
		//Z: this bit shall be set to zero for synchronization purposes in serial communication links
		//z := nextByte & 0x01 != 0

		nextByte, readErr = padReader.ReadByte()
		if readErr != nil {
			if mVerbose { fmt.Printf("PadReader error: %s\n", readErr) }
		}

		//F-PAD type: this 2-bit field shall indicate the content of the Byte L-1 data field. The values "01", "10" and "11" are reserved for future use of the Byte L-1 data field.
		fpadType := (nextByte & 0xC0) >> 6
		//X-PAD Ind (X-PAD Indicator): this 2-bit field shall indicate the presence and length of the X-PAD field
		xpadIndicator := XPadIndicator((nextByte & 0x30) >> 4)

		//fmt.Printf("PadParse: Ci: %5t, Z: %5t, FPadType: 0x%02X, XpadId: %d\n", ciPresent, z, fpadType, xpadIndicator)

		if fpadType == 0x00 {
			//map[lengthOfXpadDataSubField] PadApplicationType
			var xpadApps []parsedXpadApp

			switch xpadIndicator {
			case No_Xpad:
				//fmt.Printf("No XPAD present\n")
			case Short_Xpad:
				//fmt.Printf("Short XPAD present\n")
				xpadSize := uint8(0x04)
				curPadAppType := PAD_APP_NOT_USED
				if ciPresent {
					nextByte, readErr = padReader.ReadByte()
					if readErr != nil {
						if mVerbose { fmt.Printf("PadReader error: %s\n", readErr) }
					}
					curPadAppType = PadApplicationType(nextByte & 0x1F)
					curPdp.previousPadAppType = curPadAppType
					xpadSize = 3
				} else {
					curPadAppType = curPdp.previousPadAppType+1
				}
				//fmt.Printf("XPAD Size: %d\n", xpadSize)

				xpadApps = append(xpadApps, parsedXpadApp{
					dataSubfieldLen: xpadSize,
					padAppType:      curPadAppType,
				})

			case Variable_Xpad:
				if ciPresent {
					for cIi := 0; cIi < 4; cIi++ {
						nextByte, readErr = padReader.ReadByte()
						if readErr != nil {
							if mVerbose { fmt.Printf("PadReader error: %s\n", readErr) }
						}

						xpadLengthIdx := (nextByte & 0xE0) >> 5
						curPadAppType := PadApplicationType(nextByte & 0x1F)

						if curPadAppType == 0 {
							//fmt.Printf("XPAD End marker\n")
							break
						}

						curPdp.previousPadAppType = curPadAppType
						curPdp.previousXpadSize = XPadSize[xpadLengthIdx]

						xpadApps = append(xpadApps, parsedXpadApp{
							dataSubfieldLen: curPdp.previousXpadSize,
							padAppType:      curPadAppType,
						})
					}
				} else {
					if curPdp.previousXpadSize > 0 || curPdp.previousPadAppType != 0xFF {
						if curPdp.previousPadAppType % 2 == 0 {
							curPdp.previousPadAppType += 1
						}

						xpadApps = append(xpadApps, parsedXpadApp{
							dataSubfieldLen: uint8(len(padData) - 2),
							padAppType:      curPdp.previousPadAppType,
						})
					} else {
						if mVerbose { fmt.Printf("XPAD continuation error\n") }
					}
				}

			case RFU_XPad:
				if mVerbose { fmt.Printf("RFU XPAD present\n") }
			}

			for _, xpadApp := range xpadApps {
				dataSubfield := make([]byte, xpadApp.dataSubfieldLen)
				read, err := padReader.Read(dataSubfield)
				if err != nil || read != int(xpadApp.dataSubfieldLen) {
					if mVerbose { fmt.Printf("Error reading XPAD data subfield. Wanted %d, got only %d bytes. %s\n", xpadApp.dataSubfieldLen, read, err) }
				}

				switch xpadApp.padAppType {
				case PAD_APP_DLS_DATAGROUP_START:
					fallthrough
				case PAD_APP_DLS_DATAGROUP_CONTINUATION:
					processDls(dataSubfield, xpadApp.padAppType, subchannelId, afSeqNum)

				case PAD_APP_DATA_GROUP_LENGTH_INDICATOR:
					fallthrough
				case PAD_APP_MOT_DATAGROUP_START:
					fallthrough
				case PAD_APP_MOT_DATAGROUP_CONTINUATION:
					buildMotDatagroup(dataSubfield, xpadApp.padAppType, subchannelId)
				}
			}
		} else {
			if mVerbose { fmt.Printf("Wrong F-PAD type: %d\n", fpadType) }
		}

		break
	}
}

type DlsSegmentType uint8
const (
	DLS_SEGMENT_INTERMEDIATE	DlsSegmentType = 0
	DLS_SEGMENT_LAST			DlsSegmentType = 1
	DLS_SEGMENT_FIRST			DlsSegmentType = 2
	DLS_SEGMENT_ONE_AND_ONLY	DlsSegmentType = 3
)

type DlsDataProcessor struct {
	dlDataGroup		[]byte
	dlDataGroupStartAfSeq	uint16
	labelData		map[uint8][]byte
	fullLabelData	[]byte
	fullLabel		string
	charset			uint8
	hasDlPlus		bool
	segmentNum		uint8
	toggleState		bool
	itemRunning		bool
	toggleAfSeqNum	uint16
	dgReceiveTime	time.Time
	dlStartTime		time.Time
}

type DlsCommand uint8
const (
	DLS_COMMAND_UNKNOWN			DlsCommand = 0
	DLS_COMMAND_CLEAR_DISPLAY	DlsCommand = 1
	DLS_COMMAND_DL_PLUS			DlsCommand = 2
)

var (
	mDlsDataProcessors = make(map[uint8] *DlsDataProcessor)
	mDlsDataProcessorsMutex = sync.RWMutex{}
)
func processDls(dlsData []byte, appType PadApplicationType, subchannelId uint8, afSeqNum uint16) {
	//fmt.Printf("Processing DLS for SubchanId: 0x%02X and PadAppType: %d\n", subchannelId, appType)

	mDlsDataProcessorsMutex.Lock()
	if _, dlsdpExists := mDlsDataProcessors[subchannelId]; !dlsdpExists {
		if mVerbose { fmt.Printf("Adding new DLS DataProcessor for SubchanId: 0x%02X\n", subchannelId) }

		newDlsDp := new(DlsDataProcessor)
		newDlsDp.dlDataGroup = make([]byte, 0)
		newDlsDp.labelData = make(map[uint8][]byte)
		newDlsDp.charset = 0xFF
		newDlsDp.hasDlPlus = false
		newDlsDp.segmentNum = 0

		mDlsDataProcessors[subchannelId] = newDlsDp
	}

	curDlsDp := mDlsDataProcessors[subchannelId]
	mDlsDataProcessorsMutex.Unlock()

	if appType == PAD_APP_DLS_DATAGROUP_START {
		if len(curDlsDp.dlDataGroup) >= 4 {
			//Last segment complete
			dlsDataReader := bytes.NewReader(curDlsDp.dlDataGroup)

			nextByte, readErr := dlsDataReader.ReadByte()
			if readErr != nil {
				if mVerbose { fmt.Printf("DLS Reader error: %s\n", readErr) }
			}

			//toggleBit := (nextByte & 0x80) >> 7 != 0
			firstLast := (nextByte & 0x60) >> 5
			//segmentType := DlsSegmentType((nextByte & 0x60) >> 5)
			segmentType := DlsSegmentType(firstLast)
			commandFlag := (nextByte & 0x10 )>> 4 != 0

			if !commandFlag {
				labelDataLen := (nextByte & 0x0F) + 1

				if len(curDlsDp.dlDataGroup) <= int(labelDataLen)+2 {
					if mVerbose { fmt.Printf("Too less LabelData: %d need %d+2 - %s\n", len(curDlsDp.dlDataGroup), labelDataLen, curDlsDp.dlDataGroup) }
					curDlsDp.dlDataGroup = nil
					curDlsDp.labelData = make(map[uint8][]byte)
					return
				}

				//Trim padding
				if len(curDlsDp.dlDataGroup) > int(labelDataLen)+4 {
					curDlsDp.dlDataGroup = curDlsDp.dlDataGroup[:labelDataLen+4]
				}

				dlsCrc := crc16.ChecksumCCITTFalse(curDlsDp.dlDataGroup)
				if dlsCrc != 0x1D0f {
					if mVerbose { fmt.Printf("DLSE wrong CRC: 0x%04X 0x%02X%02X\n", dlsCrc, curDlsDp.dlDataGroup[len(curDlsDp.dlDataGroup)-2], curDlsDp.dlDataGroup[len(curDlsDp.dlDataGroup)-1]) }
					curDlsDp.dlDataGroup = nil
					return
				}

				nextByte, readErr = dlsDataReader.ReadByte()
				if readErr != nil {
					if mVerbose { fmt.Printf("DlsReader error: %s\n", readErr) }
				}

				switch segmentType {
				case DLS_SEGMENT_FIRST:
					curDlsDp.charset = (nextByte & 0x0F) >> 4
					curDlsDp.segmentNum = 0

					curDlsDp.fullLabelData = make([]byte, 0)
					curDlsDp.labelData = make(map[uint8][]byte)
					curDlsDp.toggleAfSeqNum = curDlsDp.dlDataGroupStartAfSeq
					curDlsDp.dlStartTime = curDlsDp.dgReceiveTime

					labelData := make([]byte, labelDataLen)
					_, _ = dlsDataReader.Read(labelData)

					curDlsDp.labelData[0] = labelData

				case DLS_SEGMENT_INTERMEDIATE:
					segmentNum := (nextByte & 0x70) >> 4

					if len(curDlsDp.labelData) > 0 {
						labelData := make([]byte, labelDataLen)
						_, _ = dlsDataReader.Read(labelData)

						if _, segExists := curDlsDp.labelData[segmentNum]; !segExists {
							if curDlsDp.segmentNum+1 != segmentNum {
								curDlsDp.dlDataGroup = nil
								curDlsDp.segmentNum = 0
								curDlsDp.labelData = make(map[uint8][]byte)
								break
							}

							curDlsDp.segmentNum = segmentNum

							curDlsDp.labelData[segmentNum] = labelData
						} else {
							if mVerbose { fmt.Printf("DLSSegmentInterm %d already exists. Data: %s - %s\n", segmentNum, curDlsDp.labelData[segmentNum], labelData) }
						}
					} else {
						if mVerbose { fmt.Printf("DLSE SegmentInterm data empty\n") }
					}
				case DLS_SEGMENT_LAST:
					segmentNum := (nextByte % 0x70) >> 4

					if len(curDlsDp.labelData) > 0 {
						if curDlsDp.segmentNum+1 != segmentNum {
							curDlsDp.dlDataGroup = nil
							curDlsDp.segmentNum = 0
							curDlsDp.labelData = make(map[uint8][]byte)
							break
						}

						labelData := make([]byte, labelDataLen)
						_, _ = dlsDataReader.Read(labelData)

						if _, segExists := curDlsDp.labelData[segmentNum]; segExists {
							if mVerbose { fmt.Printf("DLSE SegmentLaster %d already exists. Data: %s - %s\n", segmentNum, curDlsDp.labelData[segmentNum], labelData) }
						}

						curDlsDp.labelData[segmentNum] = labelData

						var fullDlBytes []byte = make([]byte, 0)
						for i := 0; i < int(segmentNum+1); i++ {
							curDlsDp.fullLabelData = append(curDlsDp.fullLabelData, curDlsDp.labelData[uint8(i)]...)
							fullDlBytes = append(fullDlBytes, curDlsDp.labelData[uint8(i)]...)
						}

						curDlsDp.fullLabel = convertToEbuLatin(fullDlBytes, curDlsDp.charset)

					} else {
						if mVerbose { fmt.Printf("DLSSegmentLaster data empty\n") }
					}

					curDlsDp.dlDataGroup = nil

				case DLS_SEGMENT_ONE_AND_ONLY:
					curDlsDp.charset = (nextByte & 0x0F) >> 4
					//4 bit RFA

					labelData := make([]byte, labelDataLen)
					_, _ = dlsDataReader.Read(labelData)

					curDlsDp.fullLabelData = labelData

					curDlsDp.fullLabel = convertToEbuLatin(labelData, curDlsDp.charset)

					curDlsDp.dlDataGroup = nil
				}
			} else {
				for t := 0; t < len(curDlsDp.dlDataGroup); t++ {
					if curDlsDp.dlDataGroup[len(curDlsDp.dlDataGroup)-1] == 0x00 {
						curDlsDp.dlDataGroup = curDlsDp.dlDataGroup[:len(curDlsDp.dlDataGroup)-1]
					} else {
						break
					}
				}

				dlsCrc := crc16.ChecksumCCITTFalse(curDlsDp.dlDataGroup)
				if dlsCrc != 0x1D0f {
					if mVerbose { fmt.Printf("DLSC CRC: 0x%04X 0x%02X%02X\n", dlsCrc, curDlsDp.dlDataGroup[len(curDlsDp.dlDataGroup)-2], curDlsDp.dlDataGroup[len(curDlsDp.dlDataGroup)-1]) }
					curDlsDp.dlDataGroup = nil
					return
				}

				dlCommand := DlsCommand(nextByte & 0x0F)

				switch dlCommand {
				case DLS_COMMAND_UNKNOWN:
					fallthrough
				case DLS_COMMAND_CLEAR_DISPLAY:
					curDlsDp.dlDataGroup = nil
				case DLS_COMMAND_DL_PLUS:
					nextByte, readErr = dlsDataReader.ReadByte()
					if readErr != nil {
						if mVerbose { fmt.Printf("DLSC Reader error: %s\n", readErr) }
					}

					//Field 2
					//First flag = 1
					var linkBit bool
					if segmentType == DLS_SEGMENT_FIRST || segmentType == DLS_SEGMENT_ONE_AND_ONLY {
						linkBit = (nextByte & 0x80) >> 7 != 0
					}
					//First flag = 0
					if segmentType == DLS_SEGMENT_INTERMEDIATE || segmentType == DLS_SEGMENT_LAST {
						linkBit = (nextByte & 0x80) >> 7 != 0
						segNum := (nextByte & 0x70) >> 4
						if mVerbose { fmt.Printf("DLSC SegNum: %d\n", segNum) }
					}

					//Field 3
					dlCommandLen := nextByte & 0x0F

					nextByte, readErr = dlsDataReader.ReadByte()
					if readErr != nil {
						if mVerbose { fmt.Printf("DLSC Reader error: %s - %d - %t\n", readErr, dlCommandLen, linkBit) }
					}

					cId := (nextByte & 0xF0) >> 4

					if cId == 0x00 {
						if len(curDlsDp.labelData) > 0 {
							itemToggle := (nextByte & 0x08) >> 3 != 0
							itemRunning := (nextByte & 0x04) >> 2 != 0

							numTags := (nextByte & 0x03) + 0x01

							var dlpTags []DlPlusTag
							for tagCnt := uint8(0); tagCnt < numTags; tagCnt++ {
								var dlpTag DlPlusTag
								cidByte, readErr := dlsDataReader.ReadByte()
								if readErr != nil {
									if mVerbose { fmt.Printf("DLST Reader error: %s\n", readErr) }
								}

								contentId := cidByte & 0x7F
								dlpTag.DlPlusContentType = DlPlusContentType(contentId)
								dlpTag.DlPlusContentTypeDesc = DlPlusContentTypeString[contentId]

								startByte, readErr := dlsDataReader.ReadByte()
								if readErr != nil {
									if mVerbose { fmt.Printf("DLST Reader error: %s\n", readErr) }
								}

								startMarker := int(startByte & 0x7F)

								lenByte, readErr := dlsDataReader.ReadByte()
								if readErr != nil {
									if mVerbose { fmt.Printf("DLST Reader error: %s\n", readErr) }
								}

								lengthMarker := int(lenByte & 0x7F)

								if dlpTag.DlPlusContentType != DLP_CONTENT_TYPE_DUMMY {
									if len(curDlsDp.fullLabelData) >= startMarker+lengthMarker+1 {
										dlpTagTextData := curDlsDp.fullLabelData[startMarker : startMarker+lengthMarker+1]

										dlpTag.DlPlusTagText = convertToEbuLatin(dlpTagTextData, curDlsDp.charset)
									} else {
										if mVerbose { fmt.Printf("DLST endmarker out of bounds. Start: %d, Length: %d, Label: %s, LabelLen: %d\n", startMarker, lengthMarker, curDlsDp.fullLabel, len(curDlsDp.fullLabel)) }
									}
								}

								dlpTags = append(dlpTags, dlpTag)
							}

							if curDlsDp.hasDlPlus {
								if curDlsDp.itemRunning != itemRunning || curDlsDp.toggleState != itemToggle {
									if mVerbose { fmt.Printf("%s : DLST Toggle: %5t was %5t, Running: %5t was %5t, NumTags: %d at AfSeqNum: %d, %s\n", time.Now().Format(time.UnixDate), curDlsDp.toggleState, itemToggle, itemRunning, curDlsDp.toggleState, numTags, curDlsDp.toggleAfSeqNum, curDlsDp.fullLabel) }
									curDlsDp.itemRunning = itemRunning
									curDlsDp.toggleState = itemToggle

									MAfWrapMultiMapMutex.Lock()
									toggledDl := DynamicLabel{
										FullLabel:        	curDlsDp.fullLabel,
										Tags:             	dlpTags,
										ItemToggleState:  	itemToggle,
										ItemRunningState: 	itemRunning,
										SubchanId:			subchannelId,
										AfSeqNum:			curDlsDp.toggleAfSeqNum,
										AfMulti:			MAfWrapMultiMap[subchannelId],
										ReceiveTime:		curDlsDp.dlStartTime.UnixNano()/1000000,
									}
									MAfWrapMultiMapMutex.Unlock()

									mToggleCallback(toggledDl)
								}
							} else {
								if mVerbose { fmt.Printf("ToggleC initializing state. Toggle: %5t, Running: %5t\n", itemToggle, itemRunning) }
								//For false positives on first toggle
								curDlsDp.hasDlPlus = true

								curDlsDp.itemRunning = itemRunning
								curDlsDp.toggleState = itemToggle
							}

						}
					}
				}
			}
		}

		//First received DLS data
		curDlsDp.dgReceiveTime = time.Now()
		curDlsDp.dlDataGroup = nil
		curDlsDp.dlDataGroup = append(curDlsDp.dlDataGroup, dlsData...)
		curDlsDp.dlDataGroupStartAfSeq = afSeqNum
	}

	if appType == PAD_APP_DLS_DATAGROUP_CONTINUATION {
		if len(curDlsDp.dlDataGroup) > 0 {
			curDlsDp.dlDataGroup = append(curDlsDp.dlDataGroup, dlsData...)
		}
	}
}

type DynamicLabel struct {
	FullLabel			string			`json:"label"`
	Tags				[]DlPlusTag		`json:"tags"`
	ItemToggleState		bool			`json:"toggleState"`
	ItemRunningState	bool			`json:"runningState"`

	//
	SubchanId			uint8			`json:"-"`
	AfSeqNum			uint16			`json:"-"`
	AfMulti				uint16			`json:"-"`
	ReceiveTime			int64			`json:"time"`
	ToggleId			int64			`json:"id"`
	SlidePath			string			`json:"slidePath"`
	SlideMime			string			`json:"slideMime"`
}

type DlPlusTag struct {
	DlPlusContentType					`json:"type"`
	DlPlusContentTypeDesc 	string	 	`json:"typeDescription"`
	DlPlusTagText			string		`json:"text"`
}

type DlPlusContentType uint8
const (
	DLP_CONTENT_TYPE_DUMMY						DlPlusContentType =  0
	DLP_CONTENT_TYPE_ITEM_TITLE					DlPlusContentType =  1
	DLP_CONTENT_TYPE_ITEM_ALBUM					DlPlusContentType =  2
	DLP_CONTENT_TYPE_ITEM_TRACKNUMBER			DlPlusContentType =  3
	DLP_CONTENT_TYPE_ITEM_ARTIST				DlPlusContentType =  4
	DLP_CONTENT_TYPE_ITEM_COMPOSITION			DlPlusContentType =  5
	DLP_CONTENT_TYPE_ITEM_MOVEMENT				DlPlusContentType =  6
	DLP_CONTENT_TYPE_ITEM_CONDUCTOR				DlPlusContentType =  7
	DLP_CONTENT_TYPE_ITEM_COMPOSER				DlPlusContentType =  8
	DLP_CONTENT_TYPE_ITEM_BAND					DlPlusContentType =  9
	DLP_CONTENT_TYPE_ITEM_COMMENT				DlPlusContentType = 10
	DLP_CONTENT_TYPE_ITEM_GENRE					DlPlusContentType = 11

	DLP_CONTENT_TYPE_INFO_NEWS					DlPlusContentType = 12
	DLP_CONTENT_TYPE_INFO_NEWS_LOCAL			DlPlusContentType = 13
	DLP_CONTENT_TYPE_INFO_STOCKMARKET			DlPlusContentType = 14
	DLP_CONTENT_TYPE_INFO_SPORT					DlPlusContentType = 15
	DLP_CONTENT_TYPE_INFO_LOTTERY				DlPlusContentType = 16
	DLP_CONTENT_TYPE_INFO_HOROSCOPE				DlPlusContentType = 17
	DLP_CONTENT_TYPE_INFO_DAILY_DIVERSION		DlPlusContentType = 18
	DLP_CONTENT_TYPE_INFO_HEALTH				DlPlusContentType = 19
	DLP_CONTENT_TYPE_INFO_EVENT					DlPlusContentType = 20
	DLP_CONTENT_TYPE_INFO_SCENE					DlPlusContentType = 21
	DLP_CONTENT_TYPE_INFO_CINEMA				DlPlusContentType = 22
	DLP_CONTENT_TYPE_INFO_TV					DlPlusContentType = 23
	DLP_CONTENT_TYPE_INFO_DATE_TIME				DlPlusContentType = 24
	DLP_CONTENT_TYPE_INFO_WEATHER				DlPlusContentType = 25
	DLP_CONTENT_TYPE_INFO_TRAFFIC				DlPlusContentType = 26
	DLP_CONTENT_TYPE_INFO_ALARM					DlPlusContentType = 27
	DLP_CONTENT_TYPE_INFO_ADVERTISEMENT			DlPlusContentType = 28
	DLP_CONTENT_TYPE_INFO_URL					DlPlusContentType = 29
	DLP_CONTENT_TYPE_INFO_OTHER					DlPlusContentType = 30
	DLP_CONTENT_TYPE_STATIONNAME_SHORT			DlPlusContentType = 31
	DLP_CONTENT_TYPE_STATIONNAME_LONG			DlPlusContentType = 32
	DLP_CONTENT_TYPE_PROGRAMME_NOW				DlPlusContentType = 33
	DLP_CONTENT_TYPE_PROGRAMME_NEXT				DlPlusContentType = 34
	DLP_CONTENT_TYPE_PROGRAMME_PART				DlPlusContentType = 35
	DLP_CONTENT_TYPE_PROGRAMME_HOST				DlPlusContentType = 36
	DLP_CONTENT_TYPE_PROGRAMME_EDITORIAL_STAFF	DlPlusContentType = 37
	DLP_CONTENT_TYPE_PROGRAMME_FREQUENCY		DlPlusContentType = 38
	DLP_CONTENT_TYPE_PROGRAMME_HOMEPAGE			DlPlusContentType = 39
	DLP_CONTENT_TYPE_PROGRAMME_SUBCHANNEL		DlPlusContentType = 40
	DLP_CONTENT_TYPE_PHONE_HOTLINE				DlPlusContentType = 41
	DLP_CONTENT_TYPE_PHONE_STUDIO				DlPlusContentType = 42
	DLP_CONTENT_TYPE_PHONE_OTHER				DlPlusContentType = 43
	DLP_CONTENT_TYPE_SMS_STUDIO					DlPlusContentType = 44
	DLP_CONTENT_TYPE_SMS_OTHER					DlPlusContentType = 45
	DLP_CONTENT_TYPE_EMAIL_HOTLINE				DlPlusContentType = 46
	DLP_CONTENT_TYPE_EMAIL_STUDIO				DlPlusContentType = 47
	DLP_CONTENT_TYPE_EMAIL_OTHER				DlPlusContentType = 48
	DLP_CONTENT_TYPE_MMS_OTHER					DlPlusContentType = 49
	DLP_CONTENT_TYPE_CHAT						DlPlusContentType = 50
	DLP_CONTENT_TYPE_CHAT_CENTER				DlPlusContentType = 51
	DLP_CONTENT_TYPE_VOTE_QUESTION				DlPlusContentType = 52
	DLP_CONTENT_TYPE_VOTE_CENTRE				DlPlusContentType = 53

	DLP_CONTENT_TYPE_RFU_1						DlPlusContentType = 54
	DLP_CONTENT_TYPE_RFU_2						DlPlusContentType = 55

	DLP_CONTENT_TYPE_PRIVATE_CLASS_1			DlPlusContentType = 56
	DLP_CONTENT_TYPE_PRIVATE_CLASS_2			DlPlusContentType = 57
	DLP_CONTENT_TYPE_PRIVATE_CLASS_3			DlPlusContentType = 58

	DLP_CONTENT_TYPE_DESCRIPTOR_PLACE			DlPlusContentType = 59
	DLP_CONTENT_TYPE_DESCRIPTOR_APPOINTMENT		DlPlusContentType = 60
	DLP_CONTENT_TYPE_DESCRIPTOR_IDENTIFIER		DlPlusContentType = 61
	DLP_CONTENT_TYPE_DESCRIPTOR_PURCHASE		DlPlusContentType = 62
	DLP_CONTENT_TYPE_DESCRIPTOR_GET_DATA		DlPlusContentType = 63
)

var DlPlusContentTypeString = []string {
	"DUMMY",
	"ITEM_TITLE",
	"ITEM_ALBUM",
	"ITEM_TRACKNUMBER",
	"ITEM_ARTIST",
	"ITEM_COMPOSITION",
	"ITEM_MOVEMENT",
	"ITEM_CONDUCTOR",
	"ITEM_COMPOSER",
	"ITEM_BAND",
	"ITEM_COMMENT",
	"ITEM_GENRE",
	"INFO_NEWS",
	"INFO_NEWS_LOCAL",
	"INFO_STOCKMARKET",
	"INFO_SPORT",
	"INFO_LOTTERY",
	"INFO_HOROSCOPE",
	"INFO_DAILY_DIVERSION",
	"INFO_HEALTH",
	"INFO_EVENT",
	"INFO_SCENE",
	"INFO_CINEMA",
	"INFO_TV",
	"INFO_DATE_TIME",
	"INFO_WEATHER",
	"INFO_TRAFFIC",
	"INFO_ALARM",
	"INFO_ADVERTISEMENT",
	"INFO_URL",
	"INFO_OTHER",
	"STATIONNAME_SHORT",
	"STATIONNAME_LONG",
	"PROGRAMME_NOW",
	"PROGRAMME_NEXT",
	"PROGRAMME_PART",
	"PROGRAMME_HOST",
	"PROGRAMME_EDITORIAL_STAFF",
	"PROGRAMME_FREQUENCY",
	"PROGRAMME_HOMEPAGE",
	"PROGRAMME_SUBCHANNEL",
	"PHONE_HOTLINE",
	"PHONE_STUDIO",
	"PHONE_OTHER",
	"SMS_STUDIO",
	"SMS_OTHER",
	"EMAIL_HOTLINE",
	"EMAIL_STUDIO",
	"EMAIL_OTHER",
	"MMS_OTHER",
	"CHAT",
	"CHAT_CENTER",
	"VOTE_QUESTION",
	"VOTE_CENTRE",

	"RFU_1",
	"RFU_2",

	"PRIVATE_CLASS_1",
	"PRIVATE_CLASS_2",
	"PRIVATE_CLASS_3",

	"DESCRIPTOR_PLACE",
	"DESCRIPTOR_APPOINTMENT",
	"DESCRIPTOR_IDENTIFIER",
	"DESCRIPTOR_PURCHASE",
	"DESCRIPTOR_GET_DATA",
}

type MotDatagroupBuilder struct {
	subchannelId		uint8

	motDataGroupLength	uint16
	motDataGroup		[]byte
}

var (
	mMotDgBuilders = make(map[uint8] *MotDatagroupBuilder)
	mMotDgBuildersMutex = sync.RWMutex{}
)
func buildMotDatagroup(motData []byte, appType PadApplicationType, subchannelId uint8) {
	mMotDgBuildersMutex.Lock()
	if _, exists := mMotDgBuilders[subchannelId]; !exists {
		if mVerbose { fmt.Printf("Adding new MOT Processor for Subchannel: 0x%02X\n", subchannelId) }
		newMotProc := new(MotDatagroupBuilder)
		newMotProc.subchannelId = subchannelId
		newMotProc.motDataGroupLength = 0xFFFF

		mMotDgBuilders[subchannelId] = newMotProc
	}

	curMotProc := mMotDgBuilders[subchannelId]
	mMotDgBuildersMutex.Unlock()

	switch appType {
	case PAD_APP_DATA_GROUP_LENGTH_INDICATOR:
		dgliCrc := crc16.ChecksumCCITTFalse(motData)
		if dgliCrc != 0x1D0f {
			if mVerbose { fmt.Printf("MOT DGLI CRC mismatch\n") }
			curMotProc.motDataGroupLength = 0xFFFF
		}

		if len(curMotProc.motDataGroup) == int(curMotProc.motDataGroupLength) {
			processMotDatagroup(curMotProc.motDataGroup, curMotProc.subchannelId)
		}

		curMotProc.motDataGroupLength = uint16(motData[0] & 0x3F) << 8 | uint16(motData[1])
		curMotProc.motDataGroup = make([]byte, 0)
	case PAD_APP_MOT_DATAGROUP_START:
		if len(curMotProc.motDataGroup) > 0 {
			curMotProc.motDataGroupLength = 0xFFFF
			return
		}

		curMotProc.motDataGroup = motData

	case PAD_APP_MOT_DATAGROUP_CONTINUATION:
		if len(curMotProc.motDataGroup) == 0 {
			//fmt.Printf("MOT_0x%02X Datagroup is empty on DATAGROUP_CONTINUATION\n", subchannelId)
			return
		}

		remainingData := int(curMotProc.motDataGroupLength) - len(curMotProc.motDataGroup)

		if len(motData) <= remainingData {
			curMotProc.motDataGroup = append(curMotProc.motDataGroup, motData...)
		} else {
			curMotProc.motDataGroup = append(curMotProc.motDataGroup, motData[:remainingData]...)
		}

	}

}

type MotDatagroupType uint8
const (
	MOT_DG_TYPE_GENERAL_DATA			MotDatagroupType = 0
	MOT_DG_TYPE_CA_MESSAGE				MotDatagroupType = 1
	MOT_DG_TYPE_HEADER					MotDatagroupType = 3
	MOT_DG_TYPE_BODY_UNSCRAMBLED		MotDatagroupType = 4
	MOT_DG_TYPE_BODY_SCRAMBLED			MotDatagroupType = 5
	MOT_DG_TYPE_DIRECTORY_UNCOMPRESSED	MotDatagroupType = 6
	MOT_DG_TYPE_DIRECTORY_COMPRESSED	MotDatagroupType = 7
)

func processMotDatagroup(motDg []byte, subchannelId uint8) {

	motObjectsMapMutex.Lock()
	if motObjectsMap[subchannelId] == nil {
		if mVerbose { fmt.Printf("Adding new MOT Object Map for : 0x%02X\n", subchannelId) }
		motObjectsMap[subchannelId] = make(map[uint16]*MotObject)
	}
	motObjectsMapMutex.Unlock()

	dgDataReader := bytes.NewReader(motDg)

	nextByte, readErr := dgDataReader.ReadByte()
	if readErr != nil {
		if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
	}

	extensionFlag := nextByte >> 7 != 0
	crcFlag := (nextByte & 0x40) >> 6 != 0

	if crcFlag {
		dgCrc := crc16.ChecksumCCITTFalse(motDg)
		if dgCrc != 0x1D0f {
			if mVerbose { fmt.Printf("MOT_0x%02X DG CRC mismatch\n", subchannelId) }
			return
		}
	}

	segmentFlag := (nextByte & 0x20) >> 5 != 0
	userAccFlag := (nextByte & 0x10) >> 4 != 0

	datagroupType := MotDatagroupType(nextByte & 0x0F)

	nextByte, readErr = dgDataReader.ReadByte()
	if readErr != nil {
		if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
	}

	//continuityIdx := (nextByte & 0xF0) >> 4
	//repetitionIdx := nextByte & 0x0F

	if extensionFlag {
		_, readErr = dgDataReader.Read(make([]byte, 2))
		if readErr != nil {
			if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
		}
	}

	nextByte, readErr = dgDataReader.ReadByte()
	if readErr != nil {
		if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
	}

	//MSC Datagroup Session Header
	//isLast := false
	segmentNumber := uint16(0xFFFF)

	if segmentFlag {
		//isLast = nextByte >> 7 != 0
		segmentNumber = uint16(nextByte & 0x7F)

		nextByte, readErr = dgDataReader.ReadByte()
		if readErr != nil {
			if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
		}

		segmentNumber = segmentNumber << 8
		segmentNumber |= uint16(nextByte)
	}

	var transportId uint16
	var endUserAddress []byte
	if userAccFlag {
		nextByte, readErr = dgDataReader.ReadByte()
		if readErr != nil {
			if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
		}

		transportIdFlag := (nextByte & 0x10) >> 4 != 0
		lengthIndicator := nextByte & 0x0F

		if transportIdFlag {
			nextByte, readErr = dgDataReader.ReadByte()
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
			}

			transportId = uint16(nextByte) << 8

			nextByte, readErr = dgDataReader.ReadByte()
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
			}

			transportId |= uint16(nextByte)
		}

		for i := uint8(0); i < lengthIndicator-2; i++ {
			nextByte, readErr = dgDataReader.ReadByte()
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
			}

			endUserAddress = append(endUserAddress, nextByte)
		}
	}

	//Segmentation Header
	nextByte, readErr = dgDataReader.ReadByte()
	if readErr != nil {
		if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
	}

	//segmentRepititionCnt := (nextByte & 0xE0) >> 5
	segmentSize := uint16(nextByte & 0x1F) << 8

	nextByte, readErr = dgDataReader.ReadByte()
	if readErr != nil {
		if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
	}

	segmentSize |= uint16(nextByte)

	switch datagroupType {
	case MOT_DG_TYPE_HEADER:
		next7Bytes := make([]byte, 7)
		_, readErr = dgDataReader.Read(next7Bytes)
		if readErr != nil {
			if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
		}

		motBodySize := uint32(next7Bytes[0]) << 20 | uint32(next7Bytes[1]) << 12 | uint32(next7Bytes[2]) << 4 | uint32(next7Bytes[3] & 0xF0) >> 4
		//motHeaderSize := uint16(next7Bytes[3] & 0x0F) << 9 | uint16(next7Bytes[4]) << 1 | uint16(next7Bytes[5]) >> 7
		motContentType := MotContentType((next7Bytes[5] & 0x7E) >> 1)
		motContentSubtypeVal := uint16(next7Bytes[5] & 0x01) << 8 | uint16(next7Bytes[6])

		//Header Extension
		extHdrParams := make(map[uint8][]byte)
		for {
			nextByte, readErr = dgDataReader.ReadByte()
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDGHdr Reader error: %s\n", readErr) }
				break
			}

			extParamLengthIndicator := (nextByte & 0xC0) >> 6
			extParamId := nextByte & 0x3F

			var extHdrParamLength int
			switch extParamLengthIndicator {
			case 0:
				//no data field
				continue
			case 1:
				//1 byte data field
				extHdrParamLength = 1
			case 2:
				//4 bytes data field
				extHdrParamLength = 4
			case 3:
				nextByte, readErr = dgDataReader.ReadByte()
				if readErr != nil {
					if mVerbose { fmt.Printf("MOTDGHdr Reader error: %s\n", readErr) }
					break
				}

				dataFieldLenFlag := nextByte >> 7 != 0
				if dataFieldLenFlag {
					extHdrParamLength = int(nextByte & 0x7F) << 8

					nextByte, readErr = dgDataReader.ReadByte()
					if readErr != nil {
						if mVerbose { fmt.Printf("MOTDGHdr Reader error: %s\n", readErr) }
						break
					}

					extHdrParamLength |= int(nextByte)
				} else {
					extHdrParamLength = int(nextByte & 0x7F)
				}
			}

			extParamData := make([]byte, extHdrParamLength)
			_, readErr = dgDataReader.Read(extParamData)
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDGHdr Reader error: %s\n", readErr) }
				break
			}

			extHdrParams[extParamId] = extParamData

			if crcFlag {
				if dgDataReader.Len() <= 2 {
					break
				}
			}
		}

		motObjectsMapMutex.Lock()
		newMotObject := new(MotObject)
		newMotObject.subchannelId = subchannelId
		newMotObject.transportId = transportId
		newMotObject.bodyData = make(map[uint16][]byte)
		newMotObject.bodySize = motBodySize
		newMotObject.contentType = motContentType
		newMotObject.contentSubType = motContentSubtypeVal
		newMotObject.headerParams = extHdrParams

		motObjectsMap[subchannelId][transportId] = newMotObject
		motObjectsMapMutex.Unlock()

	case MOT_DG_TYPE_BODY_UNSCRAMBLED:
		motObjectsMapMutex.Lock()
		if motObjectPtr := motObjectsMap[subchannelId][transportId]; motObjectPtr != nil {
			bodyDataBytes := make([]byte, segmentSize)
			_, readErr = dgDataReader.Read(bodyDataBytes)
			if readErr != nil {
				if mVerbose { fmt.Printf("MOTDG Reader error: %s\n", readErr) }
			}

			motObjectPtr.bodyData[segmentNumber] = bodyDataBytes
			motObjectPtr.bodiesData = append(motObjectPtr.bodiesData, bodyDataBytes...)

			if len(motObjectPtr.bodiesData) == int(motObjectPtr.bodySize) {
				//Slideshow
				if motObjectPtr.contentType == MOT_CONTENT_TYPE_IMAGE {
					var slideId 	uint8
					var catId 		uint8
					var catTitle 	string
					var triggerTime	time.Time
					var contentName	string
					receiveTime := time.Now()
					for paramId, paramData := range motObjectPtr.headerParams {
						switch MotSlideshowHeaderParam(paramId) {
						case MOT_SLS_HEADER_PARAM_EXPIRE_TIME:
							//ExpireTime
							//validityFlag := (paramData[0] & 0x80) >> 7 != 0
						case MOT_SLS_HEADER_PARAM_TRIGGER_TIME:
							//TriggerTime
							validityFlag := (paramData[0] & 0x80) >> 7 != 0
							if validityFlag {
								//TODO parse time if validityFlag
							} else {
								triggerTime = time.Now()
							}

						case MOT_SLS_HEADER_PARAM_CONTENT_NAME:
							//ContentName
							charsetIndicator := (paramData[0] & 0xF0) >> 4
							contentName = convertToEbuLatin(paramData[1:], charsetIndicator)

						case MOT_SLS_HEADER_PARAM_CAT_SLIDE_ID:
							//Cat- / SlideId
							catId = paramData[0]
							slideId = paramData[1]
						case MOT_SLS_HEADER_PARAM_CAT_TITLE:
							//category Title
							catTitle = string(paramData)
						case MOT_SLS_HEADER_PARAM_CLICK_THROUGH_URL:
							//Clickthrough URL
							//ctUrl := paramData
						case MOT_SLS_HEADER_PARAM_ALT_LOCATION_URL:
							//Alternativelocation URL
							//alLocUrl := paramData
						case MOT_SLS_HEADER_PARAM_ALERT:
							//Alert
							//fmt.Printf("SLSHdr_0x%02X Alert: 0x%X\n", subchannelId, paramData)
						}
					}

					mSlideshowCallback(MotSlideshow{
						SubchannelId:           motObjectPtr.subchannelId,
						MotContentType:         motObjectPtr.contentType,
						MotContentSubTypeImage: MotContentSubTypeImage(motObjectPtr.contentSubType),
						ContentName:            contentName,
						TriggerTime:            triggerTime,
						ReceiveTime:            receiveTime,
						ContentMime:            MotContentSubTypeImageMime[motObjectPtr.contentSubType],
						CategoryId:             catId,
						CategoryTitle:          catTitle,
						SlideId:                slideId,
						ImageData:              motObjectPtr.bodiesData,
					})
				}

				delete(motObjectsMap[subchannelId], transportId)
			}
		}
		motObjectsMapMutex.Unlock()
	}
}

var (
	motObjectsMap = make(map[uint8]map[uint16]*MotObject)
	motObjectsMapMutex = sync.RWMutex{}
)

type MotObject struct {
	subchannelId	uint8
	transportId		uint16
	bodySize		uint32
	contentType		MotContentType
	contentSubType	uint16

	headerParams	map[uint8][]byte
	bodyData		map[uint16][]byte
	bodiesData		[]byte
}

type MotSlideshow struct {
	SubchannelId			uint8
	MotContentType
	MotContentSubTypeImage
	ContentName				string
	TriggerTime				time.Time
	ReceiveTime				time.Time
	ContentMime				string
	CategoryId				uint8
	CategoryTitle			string
	SlideId					uint8
	ImageData				[]byte
}

type MotContentType uint8
const (
	MOT_CONTENT_TYPE_GENERAL_DATA	MotContentType = 0
	MOT_CONTENT_TYPE_TEXT			MotContentType = 1
	MOT_CONTENT_TYPE_IMAGE			MotContentType = 2
	MOT_CONTENT_TYPE_AUDIO			MotContentType = 3
	MOT_CONTENT_TYPE_VIDEO			MotContentType = 4
	MOT_CONTENT_TYPE_MOT_TRANSPORT	MotContentType = 5
	MOT_CONTENT_TYPE_SYSTEM			MotContentType = 6
	MOT_CONTENT_TYPE_APPLICATION	MotContentType = 7
	MOT_CONTENT_TYPE_PROPRIETARY	MotContentType = 8
)

//MotContentType == MOT_CONTENT_TYPE_IMAGE
type MotContentSubTypeImage uint16
const (
	MOT_CONTENT_SUBTYPE_IMAGE_GIF	MotContentSubTypeImage = 0
	MOT_CONTENT_SUBTYPE_IMAGE_JPEG	MotContentSubTypeImage = 1
	MOT_CONTENT_SUBTYPE_IMAGE_BMP	MotContentSubTypeImage = 2
	MOT_CONTENT_SUBTYPE_IMAGE_PNG	MotContentSubTypeImage = 3
)

type MotSlideshowHeaderParam uint8
const (
	MOT_SLS_HEADER_PARAM_EXPIRE_TIME		MotSlideshowHeaderParam = 0x04
	MOT_SLS_HEADER_PARAM_TRIGGER_TIME		MotSlideshowHeaderParam = 0x05
	MOT_SLS_HEADER_PARAM_CONTENT_NAME		MotSlideshowHeaderParam = 0x0C
	MOT_SLS_HEADER_PARAM_CAT_SLIDE_ID		MotSlideshowHeaderParam = 0x25
	MOT_SLS_HEADER_PARAM_CAT_TITLE			MotSlideshowHeaderParam = 0x26
	MOT_SLS_HEADER_PARAM_CLICK_THROUGH_URL	MotSlideshowHeaderParam = 0x27
	MOT_SLS_HEADER_PARAM_ALT_LOCATION_URL	MotSlideshowHeaderParam = 0x28
	MOT_SLS_HEADER_PARAM_ALERT				MotSlideshowHeaderParam = 0x29
)

var MotContentSubTypeImageMime = []string {
	"image/gif",
	"image/jpeg",
	"image/bmp",
	"image/png",
}

func CheckFireCode(frameData []byte) bool {
	var firstState 	uint16 = uint16(frameData[2]) << 8 | uint16(frameData[3])
	var secState	uint16

	for i:= 4; i < 11; i++ {
		secState = FireCodeTable[uint8(firstState >> 8)]
		firstState = ((secState & 0x00FF) ^ uint16(frameData[i])) | ((secState ^ firstState << 8) & 0xFF00)
	}

	for i := 0; i < 2; i++ {
		secState = FireCodeTable[uint8(firstState >> 8)]
		firstState = ((secState & 0x00FF) ^ uint16(frameData[i])) | ((secState ^ firstState << 8) & 0xFF00)
	}

	return firstState == 0
}

var FireCodeTable = [256]uint16 {
	0x0000, 0x782f, 0xf05e, 0x8871, 0x9893, 0xe0bc, 0x68cd, 0x10e2,
	0x4909, 0x3126, 0xb957, 0xc178, 0xd19a, 0xa9b5, 0x21c4, 0x59eb,
	0x9212, 0xea3d, 0x624c, 0x1a63, 0x0a81, 0x72ae, 0xfadf, 0x82f0,
	0xdb1b, 0xa334, 0x2b45, 0x536a, 0x4388, 0x3ba7, 0xb3d6, 0xcbf9,
	0x5c0b, 0x2424, 0xac55, 0xd47a, 0xc498, 0xbcb7, 0x34c6, 0x4ce9,
	0x1502, 0x6d2d, 0xe55c, 0x9d73, 0x8d91, 0xf5be, 0x7dcf, 0x05e0,
	0xce19, 0xb636, 0x3e47, 0x4668, 0x568a, 0x2ea5, 0xa6d4, 0xdefb,
	0x8710, 0xff3f, 0x774e, 0x0f61, 0x1f83, 0x67ac, 0xefdd, 0x97f2,
	0xb816, 0xc039, 0x4848, 0x3067, 0x2085, 0x58aa, 0xd0db, 0xa8f4,
	0xf11f, 0x8930, 0x0141, 0x796e, 0x698c, 0x11a3, 0x99d2, 0xe1fd,
	0x2a04, 0x522b, 0xda5a, 0xa275, 0xb297, 0xcab8, 0x42c9, 0x3ae6,
	0x630d, 0x1b22, 0x9353, 0xeb7c, 0xfb9e, 0x83b1, 0x0bc0, 0x73ef,
	0xe41d, 0x9c32, 0x1443, 0x6c6c, 0x7c8e, 0x04a1, 0x8cd0, 0xf4ff,
	0xad14, 0xd53b, 0x5d4a, 0x2565, 0x3587, 0x4da8, 0xc5d9, 0xbdf6,
	0x760f, 0x0e20, 0x8651, 0xfe7e, 0xee9c, 0x96b3, 0x1ec2, 0x66ed,
	0x3f06, 0x4729, 0xcf58, 0xb777, 0xa795, 0xdfba, 0x57cb, 0x2fe4,
	0x0803, 0x702c, 0xf85d, 0x8072, 0x9090, 0xe8bf, 0x60ce, 0x18e1,
	0x410a, 0x3925, 0xb154, 0xc97b, 0xd999, 0xa1b6, 0x29c7, 0x51e8,
	0x9a11, 0xe23e, 0x6a4f, 0x1260, 0x0282, 0x7aad, 0xf2dc, 0x8af3,
	0xd318, 0xab37, 0x2346, 0x5b69, 0x4b8b, 0x33a4, 0xbbd5, 0xc3fa,
	0x5408, 0x2c27, 0xa456, 0xdc79, 0xcc9b, 0xb4b4, 0x3cc5, 0x44ea,
	0x1d01, 0x652e, 0xed5f, 0x9570, 0x8592, 0xfdbd, 0x75cc, 0x0de3,
	0xc61a, 0xbe35, 0x3644, 0x4e6b, 0x5e89, 0x26a6, 0xaed7, 0xd6f8,
	0x8f13, 0xf73c, 0x7f4d, 0x0762, 0x1780, 0x6faf, 0xe7de, 0x9ff1,
	0xb015, 0xc83a, 0x404b, 0x3864, 0x2886, 0x50a9, 0xd8d8, 0xa0f7,
	0xf91c, 0x8133, 0x0942, 0x716d, 0x618f, 0x19a0, 0x91d1, 0xe9fe,
	0x2207, 0x5a28, 0xd259, 0xaa76, 0xba94, 0xc2bb, 0x4aca, 0x32e5,
	0x6b0e, 0x1321, 0x9b50, 0xe37f, 0xf39d, 0x8bb2, 0x03c3, 0x7bec,
	0xec1e, 0x9431, 0x1c40, 0x646f, 0x748d, 0x0ca2, 0x84d3, 0xfcfc,
	0xa517, 0xdd38, 0x5549, 0x2d66, 0x3d84, 0x45ab, 0xcdda, 0xb5f5,
	0x7e0c, 0x0623, 0x8e52, 0xf67d, 0xe69f, 0x9eb0, 0x16c1, 0x6eee,
	0x3705, 0x4f2a, 0xc75b, 0xbf74, 0xaf96, 0xd7b9, 0x5fc8, 0x27e7,
}
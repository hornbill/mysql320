package native

import (
	"log"
)

// _COM_QUIT, _COM_STATISTICS, _COM_PROCESS_INFO, _COM_DEBUG, _COM_PING:
func (my *Conn) sendCmd(cmd byte) {

	my.seq = 0
	pw := my.newPktWriter(1)
	pw.writeByte(cmd)
	if my.Debug {
		log.Printf("[%2d <-] Command packet: Cmd=0x%x", my.seq-1, cmd)
	}
}

// _COM_QUERY, _COM_INIT_DB, _COM_CREATE_DB, _COM_DROP_DB, _COM_STMT_PREPARE:
func (my *Conn) sendCmdStr(cmd byte, s string) {
	my.seq = 0
	pw := my.newPktWriter(1 + len(s))
	pw.writeByte(cmd)
	pw.write([]byte(s))
	if my.Debug {
		log.Printf("[%2d <-] Command packet: Cmd=0x%x %s", my.seq-1, cmd, s)
	}
}

// _COM_PROCESS_KILL, _COM_STMT_CLOSE, _COM_STMT_RESET:
func (my *Conn) sendCmdU32(cmd byte, u uint32) {
	my.seq = 0
	pw := my.newPktWriter(1 + 4)
	pw.writeByte(cmd)
	pw.writeU32(u)
	if my.Debug {
		log.Printf("[%2d <-] Command packet: Cmd=0x%x %d", my.seq-1, cmd, u)
	}
}

func (my *Conn) sendLongData(stmtid uint32, pnum uint16, data []byte) {
	my.seq = 0
	pw := my.newPktWriter(1 + 4 + 2 + len(data))
	pw.writeByte(_COM_STMT_SEND_LONG_DATA)
	pw.writeU32(stmtid) // Statement ID
	pw.writeU16(pnum)   // Parameter number
	pw.write(data)      // payload
	if my.Debug {
		log.Printf("[%2d <-] SendLongData packet: pnum=%d", my.seq-1, pnum)
	}
}

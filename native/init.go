package native

import (
	"fmt"
	"log"
)

func (my *Conn) init() {

	my.seq = 0 // Reset sequence number, mainly for reconnect
	if my.Debug {
		log.Printf("[%2d ->] Init packet:", my.seq)
	}
	pr := my.newPktReader()

	my.info.prot_ver = pr.readByte()
	// check the protocol version
	switch my.info.prot_ver {
	case 10:
		my.handshakeV10(pr)
	case 9:
		my.handshakeV9(pr)
	default:
		panic(fmt.Errorf("Unsupported protocol version %d", my.info.prot_ver))
	}

	pr.skipAll() // Skip other information

	if my.Debug {
		log.Printf(tab8s+"ProtVer=%d, ServVer=\"%s\" Status=0x%x",
			my.info.prot_ver, my.info.serv_ver, my.status,
		)
	}
}

func (my *Conn) handshakeV10(pr *pktReader) {

	my.info.serv_ver = pr.readNTB()
	my.info.thr_id = pr.readU32()
	my.info.scramble = make([]byte, 8, 8)
	pr.readFull(my.info.scramble[0:8])
	pr.skipN(1)

	// lower two bytes of capability flags
	my.info.caps = uint32(pr.readU16())
	my.info.lang = pr.readByte()
	my.status = pr.readU16()

	// upper two bytes of capability flags
	my.info.caps += uint32(pr.readU16()) << 16

	lenPluginAuth := pr.readByte()
	if my.info.caps&_CLIENT_PLUGIN_AUTH == 0 {
		lenPluginAuth = 0
	}

	pr.skipN(10)

	if my.info.caps&_CLIENT_SECURE_CONN != 0 {

		scrambleLen := byte(20)
		if lenPluginAuth-1 >= scrambleLen {
			scrambleLen = lenPluginAuth - 1
		}
		newScramble := make([]byte, scrambleLen)
		copy(newScramble, my.info.scramble)
		my.info.scramble = newScramble

		pr.readFull(my.info.scramble[8:scrambleLen])

	}

	if my.info.caps&_CLIENT_PLUGIN_AUTH != 0 {
		my.info.authPluginName = pr.readNTB()
	}
}

func (my *Conn) handshakeV9(pr *pktReader) {

	my.info.serv_ver = pr.readNTB()
	my.info.thr_id = pr.readU32()
	my.info.scramble = pr.readNTB()

}

func (my *Conn) handshakeResponse() {
	if my.Debug {
		log.Printf("[%2d <-] Authentication packet", my.seq)
	}

	if my.info.caps&_CLIENT_PROTOCOL_41 != 0 {
		my.handshakeResponse41()
	} else {
		my.handshakeResponse320()
	}
}

func (my *Conn) handshakeResponse41() {

	flags := uint32(
		_CLIENT_PROTOCOL_41 |
			_CLIENT_LONG_PASSWORD |
			_CLIENT_LONG_FLAG |
			_CLIENT_TRANSACTIONS |
			_CLIENT_SECURE_CONN |
			_CLIENT_LOCAL_FILES |
			_CLIENT_MULTI_STATEMENTS |
			_CLIENT_MULTI_RESULTS)
	// Reset flags not supported by server
	flags &= uint32(my.info.caps) | 0xffff0000

	scrPasswd := encryptedPasswd(my.passwd, my.info.scramble[:])
	pay_len := 4 + 4 + 1 + 23 + len(my.user) + 1 + 1 + len(scrPasswd)
	if len(my.dbname) > 0 {
		pay_len += len(my.dbname) + 1
		flags |= _CLIENT_CONNECT_WITH_DB
	}
	pw := my.newPktWriter(pay_len)
	pw.writeU32(flags)
	pw.writeU32(uint32(my.max_pkt_size))
	pw.writeByte(my.info.lang)   // Charset number
	pw.writeZeros(23)            // Filler
	pw.writeNTB([]byte(my.user)) // Username
	pw.writeBin(scrPasswd)       // Encrypted password
	if len(my.dbname) > 0 {
		pw.writeNTB([]byte(my.dbname))
	}
	if len(my.dbname) > 0 {
		pay_len += len(my.dbname) + 1
		flags |= _CLIENT_CONNECT_WITH_DB
	}
	return

}

func (my *Conn) handshakeResponse320() {

	flags := uint16(
		_CLIENT_LONG_PASSWORD |
			_CLIENT_LONG_FLAG |
			_CLIENT_TRANSACTIONS |
			_CLIENT_SECURE_CONN |
			_CLIENT_LOCAL_FILES)

	scrPasswd := encryptedOldPassword(my.passwd, my.info.scramble[:])

	pay_len := 2 + 3 + (len(my.user) + 1) + (len(scrPasswd) + 1)
	if len(my.dbname) > 0 {
		pay_len += len(my.dbname) + 1
		flags |= _CLIENT_CONNECT_WITH_DB
	}

	pw := my.newPktWriter(pay_len)
	pw.writeU16(flags)
	pw.writeU24(uint32(my.max_pkt_size))

	pw.writeNTB([]byte(my.user))   // Username
	pw.writeNTB([]byte(scrPasswd)) // Encrypted password

	if len(my.dbname) > 0 {
		pw.writeNTB([]byte(my.dbname))
	}

	return
}

func (my *Conn) oldPasswd() {
	if my.Debug {
		log.Printf("[%2d <-] Password packet", my.seq)
	}
	scrPasswd := encryptedOldPassword(my.passwd, my.info.scramble[:])
	pw := my.newPktWriter(len(scrPasswd) + 1)
	pw.write(scrPasswd)
	pw.writeByte(0)
}

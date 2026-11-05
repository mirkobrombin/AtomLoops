package sealedlog

import "syscall"

var credSpace = syscall.CmsgSpace(syscall.SizeofUcred)

func passCredentials(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
}

func senderUID(oob []byte) (uint32, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		if cred, err := syscall.ParseUnixCredentials(&m); err == nil {
			return cred.Uid, true
		}
	}
	return 0, false
}

package attest

import "os"

func detectHardware() Attester {
	if dev := os.Getenv("SEV_GUEST_DEVICE"); dev != "" {

		return nil
	}
	return nil
}

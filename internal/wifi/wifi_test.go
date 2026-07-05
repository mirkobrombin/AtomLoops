package wifi

import "testing"

func TestParseScanResults(t *testing.T) {
	out := "bssid / frequency / signal level / flags / ssid\n" +
		"aa:bb:cc:dd:ee:ff\t2412\t-45\t[WPA2-PSK-CCMP][ESS]\tHomeNet\n" +
		"11:22:33:44:55:66\t5180\t-70\t[ESS]\tOpenCafe\n" +
		"\n"
	nets := parseScanResults(out)
	if len(nets) != 2 {
		t.Fatalf("want 2 networks, got %d (%+v)", len(nets), nets)
	}
	if nets[0].SSID != "HomeNet" || nets[0].Signal != -45 || !nets[0].Secure {
		t.Errorf("HomeNet parsed wrong: %+v", nets[0])
	}
	if nets[1].SSID != "OpenCafe" || nets[1].Secure {
		t.Errorf("OpenCafe should be open: %+v", nets[1])
	}
}

func TestStatusField(t *testing.T) {
	st := "bssid=aa:bb:cc:dd:ee:ff\nssid=HomeNet\nwpa_state=COMPLETED\nip_address=192.168.1.42\n"
	if v := statusField(st, "wpa_state"); v != "COMPLETED" {
		t.Errorf("wpa_state = %q, want COMPLETED", v)
	}
	if v := statusField(st, "ip_address"); v != "192.168.1.42" {
		t.Errorf("ip_address = %q", v)
	}
	if v := statusField(st, "missing"); v != "" {
		t.Errorf("missing key should be empty, got %q", v)
	}
}

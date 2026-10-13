package scanner

import "testing"

func TestScanDirEndToEnd(t *testing.T) {
	fs, err := ScanDir("../checks/testdata/fulldir", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings from fixture dir")
	}
}

package huaweicloud

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestLibdnsRecord_TXTQuoteStripping(t *testing.T) {
	zone := "example.com."

	tests := []struct {
		name     string
		record   RecordSet
		wantData string
	}{
		{
			name: "TXT record with quotes should be stripped",
			record: RecordSet{
				Name:    "_acme-challenge.example.com.",
				Type:    "TXT",
				Ttl:     300,
				Records: []string{`"abc123token"`},
			},
			wantData: "abc123token",
		},
		{
			name: "TXT record without quotes should remain unchanged",
			record: RecordSet{
				Name:    "_acme-challenge.example.com.",
				Type:    "TXT",
				Ttl:     300,
				Records: []string{"abc123token"},
			},
			wantData: "abc123token",
		},
		{
			name: "A record should not be affected",
			record: RecordSet{
				Name:    "www.example.com.",
				Type:    "A",
				Ttl:     300,
				Records: []string{"192.168.1.1"},
			},
			wantData: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, err := tt.record.libdnsRecord(zone)
			if err != nil {
				t.Fatalf("libdnsRecord() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("libdnsRecord() returned %d records, want 1", len(records))
			}
			rr := records[0].RR()
			if rr.Data != tt.wantData {
				t.Errorf("libdnsRecord() Data = %q, want %q", rr.Data, tt.wantData)
			}
		})
	}
}

func TestHwRecord_TXTQuoteAdding(t *testing.T) {
	zone := "example.com."

	tests := []struct {
		name     string
		record   libdns.Record
		wantData string
	}{
		{
			name: "TXT record without quotes should have quotes added",
			record: libdns.RR{
				Name: "_acme-challenge",
				Type: "TXT",
				TTL:  300 * time.Second,
				Data: "abc123token",
			},
			wantData: `"abc123token"`,
		},
		{
			name: "TXT record with quotes should remain unchanged",
			record: libdns.RR{
				Name: "_acme-challenge",
				Type: "TXT",
				TTL:  300 * time.Second,
				Data: `"abc123token"`,
			},
			wantData: `"abc123token"`,
		},
		{
			name: "A record should not be affected",
			record: libdns.RR{
				Name: "www",
				Type: "A",
				TTL:  300 * time.Second,
				Data: "192.168.1.1",
			},
			wantData: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hwRec, err := hwRecord(zone, tt.record)
			if err != nil {
				t.Fatalf("hwRecord() error = %v", err)
			}
			if len(hwRec.Records) != 1 {
				t.Fatalf("hwRecord() returned %d records, want 1", len(hwRec.Records))
			}
			if hwRec.Records[0] != tt.wantData {
				t.Errorf("hwRecord() Records[0] = %q, want %q", hwRec.Records[0], tt.wantData)
			}
		})
	}
}

func TestRoundTrip_TXTRecord(t *testing.T) {
	// This test verifies that a TXT record can be round-tripped through
	// hwRecord and libdnsRecord without losing data.
	// This is critical for certmagic's DNS-01 challenge to work correctly.
	zone := "example.com."
	originalValue := "acme-challenge-token-12345"

	// Step 1: Create a libdns record (as certmagic would)
	inputRecord := libdns.RR{
		Name: "_acme-challenge",
		Type: "TXT",
		TTL:  300 * time.Second,
		Data: originalValue,
	}

	// Step 2: Convert to Huawei Cloud format (for API call)
	hwRec, err := hwRecord(zone, inputRecord)
	if err != nil {
		t.Fatalf("hwRecord() error = %v", err)
	}

	// Verify quotes were added for Huawei Cloud API
	if hwRec.Records[0] != `"`+originalValue+`"` {
		t.Errorf("hwRecord() should add quotes, got %q", hwRec.Records[0])
	}

	// Step 3: Convert back from Huawei Cloud format (simulating API response)
	outputRecords, err := hwRec.libdnsRecord(zone)
	if err != nil {
		t.Fatalf("libdnsRecord() error = %v", err)
	}

	// Step 4: Verify the value matches the original
	if len(outputRecords) != 1 {
		t.Fatalf("libdnsRecord() returned %d records, want 1", len(outputRecords))
	}

	outputRR := outputRecords[0].RR()
	if outputRR.Data != originalValue {
		t.Errorf("Round-trip failed: got %q, want %q", outputRR.Data, originalValue)
	}
}
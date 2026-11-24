//go:build windows

package main

import "testing"

func TestWinevtParseXML_EventIDWithQualifiers(t *testing.T) {
	xmlText := `<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID Qualifiers="16384">7036</EventID>
    <Channel>System</Channel>
    <TimeCreated SystemTime="2026-11-11T06:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data>Spooler</Data>
    <Data>running</Data>
  </EventData>
</Event>`
	ev := winevtParseXML(xmlText, "System")
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		t.Fatal("missing detail")
	}
	if d["event_id"] != 7036 && d["event_id"] != int(7036) {
		// JSON-ish map may store int
		eid, _ := d["event_id"].(int)
		if eid != 7036 {
			t.Fatalf("event_id=%v want 7036; etype=%v summary=%v", d["event_id"], ev["etype"], ev["summary"])
		}
	}
	if ev["etype"] != "win_service_state" {
		t.Fatalf("etype=%v want win_service_state", ev["etype"])
	}
}

func TestWinevtParseXML_PlainEventID(t *testing.T) {
	xmlText := `<?xml version="1.0"?>
<Event>
  <System>
    <EventID>4624</EventID>
    <Channel>Security</Channel>
    <TimeCreated SystemTime="2026-11-11T06:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="IpAddress">10.0.0.1</Data>
    <Data Name="TargetDomainName">CORP</Data>
  </EventData>
</Event>`
	ev := winevtParseXML(xmlText, "Security")
	if ev == nil {
		t.Fatal("expected win_logon")
	}
	if ev["etype"] != "win_logon" {
		t.Fatalf("etype=%v", ev["etype"])
	}
}

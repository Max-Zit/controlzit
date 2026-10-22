package agent

import "testing"

func TestParseWingetTable(t *testing.T) {
	out := "   - \r   | \r\nName                                                               Id                                 Version         Available\n" +
		"-----------------------------------------------------------------------------------------------------------------------------------\n" +
		"Microsoft ODBC Driver 17 for SQL Server                            Microsoft.msodbcsql.17             17.10.6.1       17.11.1.1\n" +
		"Microsoft SQL Server 2025 (64-bit)                                 Microsoft.SQLServer.2025.Developer Unknown         17.0.1000.7\n" +
		"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34438 Microsoft.VCRedist.2015+.x64       14.42.34438.0   14.51.36247.0\n" +
		"Some App                                                           Some.App                           < 2.0           2.1\n" +
		"4 upgrades available.\n\nThe following packages have an upgrade available, but require explicit targeting:\n"
	got := parseWingetTable(out)
	if len(got) != 4 {
		t.Fatalf("%d rows: %+v", len(got), got)
	}
	vc := got[2]
	if vc.Name != "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34438" || vc.ID != "Microsoft.VCRedist.2015+.x64" || vc.Version != "14.42.34438.0" || vc.Available != "14.51.36247.0" {
		t.Fatalf("overflowing name: %+v", vc)
	}
	if got[1].Version != "Unknown" || got[3].Version != "< 2.0" || got[3].Available != "2.1" {
		t.Fatalf("versions: %+v %+v", got[1], got[3])
	}
	search := "Name           Id                      Version\n---------------------------------------------\n7-Zip          7zip.7zip               24.09\nNotepad++      Notepad++.Notepad++     8.7\n"
	s := parseWingetTable(search)
	if len(s) != 2 || s[1].ID != "Notepad++.Notepad++" || s[0].Version != "24.09" || s[0].Available != "" {
		t.Fatalf("search: %+v", s)
	}
	if parseWingetTable("No installed package found matching input criteria.") != nil {
		t.Fatal("no table")
	}
}

func TestParseWingetListEmptyColumns(t *testing.T) {
	out := "Name                                                               Id                                 Version         Available\n" +
		"-----------------------------------------------------------------------------------------------------------------------------------\n" +
		"Microsoft Edge                                                     Microsoft.Edge                     155.0.4283.62   \n" +
		"Microsoft ODBC Driver 17 for SQL Server                            Microsoft.msodbcsql.17             17.10.6.1       17.11.1.1\n" +
		"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34438 Microsoft.VCRedist.2015+.x64       14.42.34438.0   14.51.36247.0\n" +
		"7-Zip 24.09 (x64)                                                  7zip.7zip                          24.09\n"
	got := parseWingetTable(out)
	if len(got) != 4 {
		t.Fatalf("%d rows: %+v", len(got), got)
	}
	if got[0].ID != "Microsoft.Edge" || got[0].Version != "155.0.4283.62" || got[0].Available != "" {
		t.Fatalf("empty Available: %+v", got[0])
	}
	if got[3].ID != "7zip.7zip" || got[3].Version != "24.09" || got[3].Name != "7-Zip 24.09 (x64)" {
		t.Fatalf("short row: %+v", got[3])
	}
	if got[2].ID != "Microsoft.VCRedist.2015+.x64" || got[2].Available != "14.51.36247.0" {
		t.Fatalf("overflow: %+v", got[2])
	}
}

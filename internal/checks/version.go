package checks

import (
	"github.com/Dv2Corn/xui-doctor/internal/version"
)

// ReleaseRepo returns the GitHub repository whose releases a panel kind follows.
func ReleaseRepo(kind string) string {
	if kind == KindStillUI {
		return "Dv2Corn/still-ui"
	}
	return "MHSanaei/3x-ui"
}

func checkVersion(s *Snapshot) []Finding {
	if s.Status == nil {
		if f, ok := s.skipped("status"); ok {
			return []Finding{f}
		}
		return nil
	}
	name := s.Kind
	cur := s.Status.PanelVersion
	desc := name + " " + cur
	if s.Kind == KindStillUI && s.Status.UpstreamVersion != "" {
		desc += " (based on 3x-ui " + s.Status.UpstreamVersion + ")"
	}
	if s.Offline {
		return []Finding{{Severity: Info, Subject: "panel", Message: desc + "; latest release not looked up (--offline)"}}
	}
	if s.LatestReleaseErr != "" {
		return []Finding{{Severity: Info, Subject: "panel", Message: desc + "; latest release lookup failed: " + s.LatestReleaseErr}}
	}
	cv, ok1 := version.Parse(cur)
	lv, ok2 := version.Parse(s.LatestRelease)
	if !ok1 || !ok2 {
		return []Finding{{Severity: Info, Subject: "panel", Message: desc + "; latest release is " + s.LatestRelease}}
	}
	if version.Compare(cv, lv) < 0 {
		return []Finding{{Severity: Warn, Subject: "panel",
			Message: desc + " is older than the latest release " + lv.String() + " of " + ReleaseRepo(s.Kind),
			Fix:     "Read the release notes, back up the database, then update from the panel or with the install script."}}
	}
	return []Finding{{Severity: OK, Subject: "panel", Message: desc + " is the latest release"}}
}

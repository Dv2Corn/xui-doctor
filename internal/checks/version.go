package checks

import (
	"github.com/Dv2Corn/xui-doctor/internal/i18n"
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
	cur := s.Status.PanelVersion
	desc := i18n.T("version.desc", s.Kind, cur)
	if s.Kind == KindStillUI && s.Status.UpstreamVersion != "" {
		desc = i18n.T("version.desc_based", s.Kind, cur, s.Status.UpstreamVersion)
	}
	panel := i18n.T("subj.panel")
	if s.Offline {
		return []Finding{newFinding(Info, panel, i18n.T("version.offline", desc), i18n.Text{})}
	}
	if s.LatestReleaseErr != "" {
		return []Finding{newFinding(Info, panel, i18n.T("version.lookup_failed", desc, s.LatestReleaseErr), i18n.Text{})}
	}
	cv, ok1 := version.Parse(cur)
	lv, ok2 := version.Parse(s.LatestRelease)
	if !ok1 || !ok2 {
		return []Finding{newFinding(Info, panel, i18n.T("version.latest_is", desc, s.LatestRelease), i18n.Text{})}
	}
	if version.Compare(cv, lv) < 0 {
		return []Finding{newFinding(Warn, panel, i18n.T("version.outdated", desc, lv.String(), ReleaseRepo(s.Kind)),
			i18n.T("version.outdated.fix"))}
	}
	return []Finding{newFinding(OK, panel, i18n.T("version.latest", desc), i18n.Text{})}
}

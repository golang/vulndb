package report

//CvssScoreToSeverity calculate severity by cvss version and score
//accept cvss version and score , return severity
func CvssScoreToSeverity(cvss *CVSS) string {
	if cvss == nil {
		return ""
	}
	switch cvss.Version {
	case "v2":
		return cvssV2SeverityByScore(cvss.BaseScore)
	case "v3":
		return cvssV3SeverityByScore(cvss.BaseScore)
	default:
		return ""
	}
}

func cvssV3SeverityByScore(score float32) string {
	switch {
	case score == 0.0:
		return "None"
	case score >= 0.1 && score <= 3.9:
		return "Low"
	case score >= 4.0 && score <= 6.9:
		return "Medium"
	case score >= 7.0 && score <= 8.9:
		return "High"
	case score >= 9.0 && score <= 10.0:
		return "Critical"
	default:
		return ""
	}
}

func cvssV2SeverityByScore(score float32) string {
	switch {
	case score >= 0.0 && score <= 3.9:
		return "Low"
	case score >= 4.0 && score <= 6.9:
		return "Medium"
	case score >= 7.0 && score <= 10.0:
		return "High"
	default:
		return "None"
	}
}

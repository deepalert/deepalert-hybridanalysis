package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/deepalert/deepalert"
	"github.com/m-mizutani/golambda"
)

type haResponse struct {
	Count       int64           `json:"count"`
	Result      []haResult      `json:"result"`
	SearchTerms []*haSearchTerm `json:"search_terms"`
}

type haSearchTerm struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type haResult struct {
	AnalysisStartTime      string      `json:"analysis_start_time"`
	AvDetect               string      `json:"av_detect"`
	EnvironmentDescription string      `json:"environment_description"`
	EnvironmentID          int64       `json:"environment_id"`
	JobID                  string      `json:"job_id"`
	Sha256                 string      `json:"sha256"`
	Size                   int64       `json:"size"`
	SubmitName             string      `json:"submit_name"`
	ThreatScore            int64       `json:"threat_score"`
	Type                   interface{} `json:"type"`
	TypeShort              string      `json:"type_short"`
	Verdict                string      `json:"verdict"`
	VxFamily               string      `json:"vx_family"`
}

const malwareReportLimit = 8

func inspect(client httpClient, token, key, value string) (*deepalert.TaskResult, error) {
	buf := strings.NewReader(fmt.Sprintf("%s=%s", key, value))
	req, err := http.NewRequest("POST", "https://www.hybrid-analysis.com/api/v2/search/terms", buf)
	if err != nil {
		return nil, golambda.WrapError(err, "Failed to create a search request")
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("user-agent", "Falcon Sandbox")
	req.Header.Add("api-key", token)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, golambda.WrapError(err, "Failed to send a search request")
	}
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			body = []byte(err.Error())
		}
		return nil, golambda.NewError("Failed search request").With("status", resp.StatusCode).With("body", string(body))
	}

	var haResp haResponse
	if err := json.NewDecoder(resp.Body).Decode(&haResp); err != nil {
		return nil, golambda.WrapError(err)
	}

	logger.With("resp", haResp).Trace("Got HybridAnalysis response")

	var malwareReport []deepalert.EntityMalware
	for _, result := range haResp.Result {
		if result.Verdict != "malicious" {
			if result.Verdict != "no specific threat" {
				logger.With("verdict", result.Verdict).Info("Skip result because of verdict")
			}
			continue
		}

		ts, err := time.Parse("2006-01-02 15:04:05", result.AnalysisStartTime)
		if err != nil {
			logger.With("AnalysisStartTime", result.AnalysisStartTime).Error("Can not parse AnalysisStartTime")
			// Just notify, no need to skip
		}

		malwareReport = append(malwareReport, deepalert.EntityMalware{
			Scans: []deepalert.EntityMalwareScan{
				{
					Vendor:   "HybridAnalysis",
					Name:     result.VxFamily,
					Positive: true,
				},
			},
			SHA256:    result.Sha256,
			Timestamp: ts,
			Relation:  "communicated",
		})
	}

	if len(malwareReport) == 0 {
		logger.Trace("No report")
		return nil, nil
	}

	sort.Slice(malwareReport, func(i, j int) bool {
		return malwareReport[i].Timestamp.After(malwareReport[j].Timestamp)
	})
	if len(malwareReport) > malwareReportLimit {
		malwareReport = malwareReport[:malwareReportLimit]
	}

	result := &deepalert.TaskResult{
		Contents: []deepalert.ReportContent{
			&deepalert.ContentHost{
				RelatedMalware: malwareReport,
			},
		},
	}
	logger.With("result", result).Trace("Got some report")
	return result, nil
}

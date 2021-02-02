package main_test

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/deepalert/deepalert"
	"github.com/deepalert/deepalert/inspector"
	"github.com/google/uuid"
	"github.com/m-mizutani/golambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	main "github.com/deepalert/deepalert-hybridanalysis/src"
)

func TestInspectorExample(t *testing.T) {
	attrURL := "https://sqs.ap-northeast-1.amazonaws.com/123456789xxx/attribute-queue"
	findingURL := "https://sqs.ap-northeast-1.amazonaws.com/123456789xxx/content-queue"
	secretARN := "arn:aws:secretsmanager:us-east-0:1234567890:secret:mytest"

	smMock, newSM := golambda.NewSecretsManagerMock()
	smMock.Secrets[secretARN] = `{"hybridanalysis_token":"bluemagic"}`

	dummyHTTP := &dummyHTTPClient{
		responses: []*http.Response{
			{
				StatusCode: http.StatusOK,
				Body: toReader(`{
	"search_terms": [
		{
		"id": "host",
		"value": "192.10.0.1"
		}
	],
	"count": 2,
	"result": [
		{
			"verdict": "no specific threat",
			"av_detect": "3",
			"threat_score": null,
			"vx_family": "Backdoor.shark",
			"job_id": "600c8a1272ff5726cb5xxxxxxxxxx",
			"sha256": "58d92183fa94efbd9f67df40259c3b4322f8231b139213bfcxxxxxxxxxfd1d1299",
			"environment_id": 100,
			"analysis_start_time": "2021-01-23 20:42:05",
			"submit_name": "Rusticaland-Launcher.exe",
			"environment_description": "Windows 7 32 bit",
			"size": 48992256,
			"type": null,
			"type_short": ".NET exe"
		},
		{
		"verdict": "malicious",
		"av_detect": "55",
		"threat_score": 100,
		"vx_family": "Trojan.Generic",
		"job_id": "5f61530740585c0541xxxxxxxxx",
		"sha256": "76cd82d1595a41e0b4ce8016d56256a2cf5ab46304d293d6f8xxxxxxxx3c2556f",
		"environment_id": 120,
		"analysis_start_time": "2020-09-15 23:49:39",
		"submit_name": "Axenta.exe",
		"environment_description": "Windows 7 64 bit",
		"size": 3061176,
		"type": null,
		"type_short": "exe"
		}
	]
}`),
			},
		},
	}

	hdlr := &main.Handler{
		SecretARN:  secretARN,
		NewSM:      newSM,
		HTTPClient: dummyHTTP,
	}

	args := inspector.Arguments{
		Context:         context.Background(),
		Handler:         hdlr.Callback,
		Author:          "blue",
		AttrQueueURL:    attrURL,
		FindingQueueURL: findingURL,
	}

	t.Run("With attribute", func(t *testing.T) {
		mock, newSQS := inspector.NewSQSMock()
		args.NewSQS = newSQS

		task := &deepalert.Task{
			ReportID: deepalert.ReportID(uuid.New().String()),
			// TODO: Add attribute to be inspected
			Attribute: &deepalert.Attribute{
				// Example:
				Type:    deepalert.TypeIPAddr,
				Key:     "dst",
				Value:   "192.10.0.1",
				Context: deepalert.AttrContexts{deepalert.CtxRemote},
			},
		}

		err := inspector.HandleTask(context.Background(), task, args)
		require.NoError(t, err)

		require.Equal(t, 1, len(dummyHTTP.requests))
		req := dummyHTTP.requests[0]
		assert.Equal(t, "https://www.hybrid-analysis.com/api/v2/search/terms", req.URL.String())
		assert.Equal(t, "bluemagic", req.Header.Get("api-key"))

		sections, err := mock.GetSections(findingURL)
		require.NoError(t, err)
		require.Equal(t, 1, len(sections))

		attributes, err := mock.GetAttributes(attrURL)
		require.NoError(t, err)
		assert.Equal(t, 0, len(attributes))
	})
}

func TestIntegration(t *testing.T) {
	dummyAttrURL := "https://sqs.ap-northeast-1.amazonaws.com/123456789xxx/attribute-queue"
	dummyFindingURL := "https://sqs.ap-northeast-1.amazonaws.com/123456789xxx/content-queue"

	secretARN, ok := os.LookupEnv("HA_SECRET_ARN")
	if !ok {
		t.Skip("HA_SECRET_ARN is not set")
	}

	t.Run("query IP address", func(t *testing.T) {
		value, ok := os.LookupEnv("HA_IPADDR")
		if !ok {
			t.Skip("HA_IPADDR is not set")
		}
		task := &deepalert.Task{
			ReportID: deepalert.ReportID(uuid.New().String()),
			Attribute: &deepalert.Attribute{
				// Example:
				Type:    deepalert.TypeIPAddr,
				Key:     "testIPAddr",
				Value:   value,
				Context: deepalert.AttrContexts{deepalert.CtxRemote},
			},
		}

		handler := &main.Handler{
			SecretARN: secretARN,
		}

		_, newSQS := inspector.NewSQSMock()
		args := inspector.Arguments{
			Context:         context.Background(),
			Tasks:           []*deepalert.Task{task},
			Handler:         handler.Callback,
			Author:          "blue",
			AttrQueueURL:    dummyAttrURL,
			FindingQueueURL: dummyFindingURL,
			NewSQS:          newSQS,
		}

		require.NoError(t, inspector.Start(args))
	})
}

type dummyHTTPClient struct {
	requests  []*http.Request
	responses []*http.Response
	seq       int
}

func (x *dummyHTTPClient) Do(req *http.Request) (*http.Response, error) {
	x.requests = append(x.requests, req)
	i := x.seq
	x.seq++
	if i >= len(x.responses) {
		panic("dummy response exceeded: ")
	}
	return x.responses[i], nil
}

func toReader(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

package main

import (
	"context"
	"net/http"
	"os"

	env "github.com/Netflix/go-env"
	"github.com/deepalert/deepalert"
	"github.com/deepalert/deepalert/inspector"
	"github.com/m-mizutani/golambda"
)

var logger = golambda.Logger

type handler struct {
	SecretARN  string `env:"SECRET_ARN"`
	NewSM      golambda.SecretsManagerFactory
	HTTPClient httpClient
}

type haSecrets struct {
	HybridAnalysisToken string `json:"hybridanalysis_token"`
}

func (x *handler) callback(ctx context.Context, attr deepalert.Attribute) (*deepalert.TaskResult, error) {
	var secrets haSecrets

	var key string
	switch {
	case attr.Match(deepalert.CtxRemote, deepalert.TypeIPAddr):
		key = "host"

	case attr.Type == deepalert.TypeDomainName:
		key = "domain"

	default:
		// nothing to do
		return nil, nil
	}

	if err := golambda.GetSecretValuesWithFactory(x.SecretARN, &secrets, x.NewSM); err != nil {
		return nil, golambda.WrapError(err).With("secretARN", x.SecretARN)
	}

	client := x.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	results, err := inspect(client, secrets.HybridAnalysisToken, key, attr.Value)
	if err != nil {
		return nil, golambda.WrapError(err).With("key", key).With("value", attr.Value)
	}

	return results, nil
}

func main() {
	golambda.Start(func(event golambda.Event) (interface{}, error) {
		bodies, err := event.DecapSNSonSQSMessage()
		if err != nil {
			return nil, err
		}

		var tasks []*deepalert.Task
		for _, body := range bodies {
			var task deepalert.Task
			if err := body.Bind(&task); err != nil {
				return nil, err
			}
			tasks = append(tasks, &task)
		}

		hdlr := &handler{}
		if _, err := env.UnmarshalFromEnviron(hdlr); err != nil {
			return nil, err
		}

		logger.With("tasks", tasks).Info("Start inspection")
		if err := inspector.Start(inspector.Arguments{
			Context:         event.Ctx,
			Tasks:           tasks,
			Handler:         hdlr.callback,
			Author:          "HybridAnalysis",
			FindingQueueURL: os.Getenv("FINDING_QUEUE_URL"),
			AttrQueueURL:    os.Getenv("ATTRIBUTE_QUEUE_URL"),
		}); err != nil {
			return nil, err
		}

		return nil, nil
	})
}

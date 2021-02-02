package main

import (
	"context"

	"github.com/deepalert/deepalert"
)

type Handler handler

func (x *Handler) Callback(ctx context.Context, attr deepalert.Attribute) (*deepalert.TaskResult, error) {
	return (*handler)(x).callback(ctx, attr)
}

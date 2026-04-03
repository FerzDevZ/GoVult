package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/FerzDevZ/GoVult/pkg/template"
	"golang.org/x/time/rate"
)

type Result struct {
	TemplateID string
	Target     string
	Severity   string
	Matched    bool
}

type Engine struct {
	Client  *http.Client
	Limiter *rate.Limiter
}

func NewEngine(rps int, proxy string) *Engine {
	transport := &http.Transport{}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &Engine{
		Client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		Limiter: rate.NewLimiter(rate.Limit(rps), 1),
	}
}

func (e *Engine) Run(target string, t *template.Template) ([]Result, error) {
	var results []Result

	for _, req := range t.Requests {
		for _, path := range req.Path {
			// Wait for rate limiter
			e.Limiter.Wait(context.Background())

			url := target + path
			httpReq, err := http.NewRequest(req.Method, url, nil)
			if err != nil {
				return nil, err
			}

			resp, err := e.Client.Do(httpReq)
			if err != nil {
				fmt.Printf("Error requesting %s: %v\n", url, err)
				continue
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if Match(string(body), resp.StatusCode, req.Matchers) {
				results = append(results, Result{
					TemplateID: t.ID,
					Target:     url,
					Severity:   t.Info.Severity,
					Matched:    true,
				})
			}

			// Run mutations if needed (only for GET params for now)
			mutatedPayloads := MutatePayload(url)
			for _, mp := range mutatedPayloads {
				if mp == url {
					continue
				}
				e.Limiter.Wait(context.Background())
				mResp, err := e.Client.Get(mp)
				if err != nil {
					continue
				}
				defer mResp.Body.Close()
				mBody, _ := io.ReadAll(mResp.Body)
				if Match(string(mBody), mResp.StatusCode, req.Matchers) {
					results = append(results, Result{
						TemplateID: t.ID,
						Target:     mp,
						Severity:   t.Info.Severity,
						Matched:    true,
					})
				}
			}
		}
	}

	return results, nil
}

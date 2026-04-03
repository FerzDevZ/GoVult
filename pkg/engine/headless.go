package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// HeadlessCrawl uses chromedp to handle SPAs and dynamic contents
func HeadlessCrawl(target string) ([]string, error) {
	fmt.Printf("[HEADLESS] Starting Chromedp on %s\n", target)

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Timeout for the entire browser session
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var links []string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.href)`, &links),
	)

	if err != nil {
		return nil, err
	}

	return links, nil
}

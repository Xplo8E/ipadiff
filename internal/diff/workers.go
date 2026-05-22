package diff

import "sync"

func workerCount(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

func runStringWorkers[T any](keys []string, workers int, fn func(string) T) []T {
	if len(keys) == 0 {
		return nil
	}
	workers = workerCount(workers)
	if workers > len(keys) {
		workers = len(keys)
	}

	jobs := make(chan string)
	results := make(chan T, len(keys))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range jobs {
				results <- fn(key)
			}
		}()
	}
	for _, key := range keys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]T, 0, len(keys))
	for result := range results {
		out = append(out, result)
	}
	return out
}

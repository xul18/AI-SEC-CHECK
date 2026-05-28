package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Orchestrator struct {
	registry *Registry
}

func NewOrchestrator(registry *Registry) *Orchestrator {
	return &Orchestrator{
		registry: registry,
	}
}

type ScanJob struct {
	PluginName string       `json:"plugin_name"`
	Target     ScanTarget   `json:"target"`
	Config     PluginConfig `json:"config,omitempty"`
}

type OrchestratorResult struct {
	Job    ScanJob     `json:"job"`
	Result *ScanResult `json:"result"`
	Error  error       `json:"error,omitempty"`
}

func (o *Orchestrator) RunSequential(ctx context.Context, jobs []ScanJob) []OrchestratorResult {
	results := make([]OrchestratorResult, 0, len(jobs))
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			results = append(results, OrchestratorResult{Job: job, Error: ctx.Err()})
			return results
		default:
		}
		result, err := o.runSingleJob(ctx, job)
		results = append(results, OrchestratorResult{Job: job, Result: result, Error: err})
	}
	return results
}

func (o *Orchestrator) RunParallel(ctx context.Context, jobs []ScanJob) []OrchestratorResult {
	results := make([]OrchestratorResult, len(jobs))
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		go func(idx int, j ScanJob) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				results[idx] = OrchestratorResult{Job: j, Error: ctx.Err()}
			default:
				result, err := o.runSingleJob(ctx, j)
				results[idx] = OrchestratorResult{Job: j, Result: result, Error: err}
			}
		}(i, job)
	}
	wg.Wait()
	return results
}

func (o *Orchestrator) RunByCategory(ctx context.Context, category string, target ScanTarget, config PluginConfig) []OrchestratorResult {
	plugins := o.registry.ListByCategory(category)
	jobs := make([]ScanJob, 0, len(plugins))
	for _, p := range plugins {
		if p.IsAvailable() {
			jobs = append(jobs, ScanJob{PluginName: p.Name(), Target: target, Config: config})
		}
	}
	return o.RunParallel(ctx, jobs)
}

func (o *Orchestrator) RunAll(ctx context.Context, target ScanTarget, config PluginConfig) []OrchestratorResult {
	plugins := o.registry.AvailablePlugins()
	jobs := make([]ScanJob, 0, len(plugins))
	for _, p := range plugins {
		jobs = append(jobs, ScanJob{PluginName: p.Name(), Target: target, Config: config})
	}
	return o.RunParallel(ctx, jobs)
}

func (o *Orchestrator) runSingleJob(ctx context.Context, job ScanJob) (*ScanResult, error) {
	p, ok := o.registry.Get(job.PluginName)
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", job.PluginName)
	}
	if !p.IsAvailable() {
		return nil, fmt.Errorf("plugin %q is not available", job.PluginName)
	}
	if err := p.ValidateTarget(job.Target); err != nil {
		return nil, fmt.Errorf("invalid target for plugin %q: %w", job.PluginName, err)
	}
	if err := p.Init(job.Config); err != nil {
		return nil, fmt.Errorf("failed to initialize plugin %q: %w", job.PluginName, err)
	}
	start := time.Now()
	result, err := p.Scan(ctx, job.Target)
	if err != nil {
		return nil, fmt.Errorf("scan failed for plugin %q: %w", job.PluginName, err)
	}
	if result != nil {
		result.Duration = time.Since(start).Seconds()
		if result.ID == "" {
			result.ID = uuid.New().String()
		}
		if result.PluginName == "" {
			result.PluginName = p.Name()
		}
		if result.Category == "" {
			result.Category = p.Category()
		}
		if result.Target == "" {
			result.Target = job.Target.Value
		}
		if result.ScanTime == "" {
			result.ScanTime = start.Format(time.RFC3339)
		}
	}
	return result, nil
}

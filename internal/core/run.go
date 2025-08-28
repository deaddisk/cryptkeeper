// Package core provides the foundational framework for cryptkeeper's modular collection system.
package core

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Module defines the interface that all collection modules must implement.
type Module interface {
	// Name returns the module's identifier, used for directory naming and reporting.
	Name() string
	// Collect performs the module's collection work, writing artifacts to outDir.
	Collect(ctx context.Context, outDir string) error
}

// Result captures the execution result of a single module.
type Result struct {
	Module    string    `json:"name"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error"`
	StartedAt time.Time `json:"started_utc"`
	EndedAt   time.Time `json:"ended_utc"`
}

// Clock provides time functions for testability.
type Clock interface {
	Now() time.Time
}

// SystemClock implements Clock using the system time.
type SystemClock struct{}

// Now returns the current system time.
func (SystemClock) Now() time.Time {
	return time.Now()
}

// Run orchestrates the execution of multiple modules with concurrency control.
type Run struct {
	modules       []Module
	parallelism   int
	moduleTimeout time.Duration
	artifactsDir  string
	clock         Clock
	logger        *log.Logger
}

// NewRun creates a new Run orchestrator.
func NewRun(parallelism int, moduleTimeout time.Duration, artifactsDir string, clock Clock, logger *log.Logger) *Run {
	if clock == nil {
		clock = SystemClock{}
	}
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	
	// Clamp parallelism to reasonable bounds
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > 64 {
		parallelism = 64
	}
	
	return &Run{
		modules:       make([]Module, 0),
		parallelism:   parallelism,
		moduleTimeout: moduleTimeout,
		artifactsDir:  artifactsDir,
		clock:         clock,
		logger:        logger,
	}
}

// Register adds a module to the execution list.
func (r *Run) Register(m Module) {
	r.modules = append(r.modules, m)
}

// CollectAll executes all registered modules concurrently with the configured constraints.
// It returns results for all modules, including those that failed.
func (r *Run) CollectAll(ctx context.Context) ([]Result, error) {
	if len(r.modules) == 0 {
		return []Result{}, nil
	}

	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, r.parallelism)
	
	// Results channel and wait group
	results := make(chan Result, len(r.modules))
	var wg sync.WaitGroup

	// Start all modules
	for _, module := range r.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result := r.executeModule(ctx, m)
			results <- result
		}(module)
	}

	// Wait for all modules to complete
	wg.Wait()
	close(results)

	// Collect results
	var allResults []Result
	var firstError error
	errorCount := 0

	for result := range results {
		allResults = append(allResults, result)
		if !result.OK && firstError == nil {
			firstError = fmt.Errorf("module %s failed: %s", result.Module, result.Error)
		}
		if !result.OK {
			errorCount++
		}
	}

	// Return aggregated error if any modules failed
	var combinedError error
	if errorCount > 0 {
		if errorCount == 1 {
			combinedError = firstError
		} else {
			combinedError = fmt.Errorf("%s (and %d other module errors)", firstError.Error(), errorCount-1)
		}
	}

	return allResults, combinedError
}

// executeModule runs a single module with timeout and error handling.
func (r *Run) executeModule(parentCtx context.Context, module Module) Result {
	startTime := r.clock.Now().UTC()
	
	// Create module-specific timeout context
	ctx, cancel := context.WithTimeout(parentCtx, r.moduleTimeout)
	defer cancel()

	// Create module output directory
	moduleDir := filepath.Join(r.artifactsDir, SanitizeName(module.Name()))
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		return Result{
			Module:    module.Name(),
			OK:        false,
			Error:     fmt.Sprintf("failed to create module directory: %v", err),
			StartedAt: startTime,
			EndedAt:   r.clock.Now().UTC(),
		}
	}

	// Execute the module
	err := module.Collect(ctx, moduleDir)
	endTime := r.clock.Now().UTC()

	if err != nil {
		r.logger.Printf("Module %s failed: %v", module.Name(), err)
		return Result{
			Module:    module.Name(),
			OK:        false,
			Error:     err.Error(),
			StartedAt: startTime,
			EndedAt:   endTime,
		}
	}

	r.logger.Printf("Module %s completed successfully", module.Name())
	return Result{
		Module:    module.Name(),
		OK:        true,
		Error:     "",
		StartedAt: startTime,
		EndedAt:   endTime,
	}
}
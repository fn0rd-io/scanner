package client

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	tasksAssigned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanner_tasks_assigned_total",
		Help: "The total number of tasks assigned to clients",
	})
	tasksCompleted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanner_tasks_completed_total",
		Help: "The total number of tasks completed successfully",
	})
	tasksFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanner_tasks_failed_total",
		Help: "The total number of tasks that failed",
	})
	streamErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanner_stream_errors_total",
		Help: "The total number of stream errors",
	})
	totalWorkers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "scanner_total_workers",
		Help: "The total number of workers across all clients",
	})
)

func (c *Client) InitMetrics() {
	if c.config.MetricsPort == "off" {
		slog.Info("Metrics disabled")
		return
	}

	//check if MetricsPort contains a ":" and if not, prefix 127.0.0.1: to it
	if !strings.Contains(c.config.MetricsPort, ":") {
		c.config.MetricsPort = "127.0.0.1:" + c.config.MetricsPort
		slog.Warn(fmt.Sprintf("Changed MetricsPort to %s", c.config.MetricsPort))
	}

	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "scanner_task_queue_depth",
		Help: "The current depth of the task queue",
	}, func() float64 {
		return float64(len(c.taskCh))
	})

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(c.config.MetricsPort, nil)
	slog.Info(fmt.Sprintf("Serving metrics on %s", c.config.MetricsPort))
}

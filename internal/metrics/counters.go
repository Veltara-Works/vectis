package metrics

import "github.com/prometheus/client_golang/prometheus"

// Counters and histograms for real-time metrics (incremented in hot paths).
var (
	EmailsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "emails_sent_total",
		Help:      "Total outbound emails sent via the API",
	})

	EmailsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "emails_received_total",
		Help:      "Total inbound emails received (notified via Postfix hook)",
	})

	EmailsSpam = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "emails_spam_total",
		Help:      "Total inbound emails classified as spam by Rspamd",
	})

	EmailsSendSuspended = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "emails_send_suspended_total",
		Help:      "Total sends blocked by abuse detection (auto-suspend)",
	})

	WebhookDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "webhook_deliveries_total",
		Help:      "Total webhook delivery attempts",
	}, []string{"status"}) // "success", "failed"

	APIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "api_requests_total",
		Help:      "Total API requests",
	}, []string{"method", "status_class"}) // method=GET/POST, status_class=2xx/4xx/5xx

	BatchMessagesSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "batch_messages_sent_total",
		Help:      "Total messages sent via the batch sending API",
	})

	FBLComplaints = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "fbl_complaints_total",
		Help:      "Total FBL (feedback loop) complaints received",
	})

	RBLListings = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "rbl_listings_current",
		Help:      "Number of RBL/DNSBL listings for server IPs",
	})

	EmailOpens = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "email_opens_total",
		Help:      "Total email open events tracked via pixel",
	})

	EmailClicks = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "email_clicks_total",
		Help:      "Total email click events tracked via redirect",
	})
)

func init() {
	prometheus.MustRegister(
		EmailsSent,
		EmailsReceived,
		EmailsSpam,
		EmailsSendSuspended,
		WebhookDeliveries,
		APIRequests,
		BatchMessagesSent,
		FBLComplaints,
		RBLListings,
		EmailOpens,
		EmailClicks,
	)
}

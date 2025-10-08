package cloudtrail

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/samsarahq/go/oops"
	"github.com/telophasehq/go-ocsf/datastore"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
	"golang.org/x/sync/errgroup"
)

const (
	defaultWorkers   = 10
	defaultBatchSize = 1000
)

// Syncer pulls CloudTrail *.json.gz files from S3 and republishes them as OCSF.
type Syncer struct {
	bucket    string     // trail bucket name
	s3        *s3.Client // injected S3 client
	ds        datastore.Datastore[ocsf.APIActivity]
	workers   int
	batchSize int
}

// New creates a new Syncer.  The bucket *must* contain standard CloudTrail keys
// (AWSLogs/<acct>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/…json.gz).
func NewSyncer(
	ctx context.Context,
	s3client *s3.Client,
	bucket string,
	storage datastore.StorageOpts,
) (*Syncer, error) {

	ds, err := datastore.SetupStorage[ocsf.APIActivity](ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("setup datastore: %w", err)
	}
	return &Syncer{
		s3:        s3client,
		bucket:    bucket,
		ds:        ds,
		workers:   defaultWorkers,
		batchSize: defaultBatchSize,
	}, nil
}

// ---------------------------------------------------------------------------
// PUBLIC API
// ---------------------------------------------------------------------------

// Sync streams every historical object plus today's keys into the datastore.
func (s *Syncer) Sync(ctx context.Context) error {
	processID := fmt.Sprintf("PROC-%d", time.Now().UnixNano())

	slog.Info("CloudTrail sync – discovery", "bucket", s.bucket)
	accRegs, err := s.discoverAccountsAndRegions(ctx)
	if err != nil {
		return err
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -30)
	cutoffDay := time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(),
		0, 0, 0, 0, time.UTC)

	workCh := make(chan string, 100)              // day prefixes
	commitCh := make(chan []ocsf.APIActivity, 64) // batches to write
	errCh := make(chan error, 1)

	if err := s.enqueueAllDays(ctx, accRegs, cutoffDay, workCh); err != nil {
		return err
	}
	close(workCh) // enqueue is done

	// ❶ single committer goroutine with WaitGroup - uses original context
	var committerWG sync.WaitGroup
	committerWG.Add(1)
	go func() {
		defer committerWG.Done()
		batchCount := 0
		totalItems := 0
		for batch := range commitCh {
			batchCount++
			batchLen := len(batch)
			totalItems += batchLen

			// Use original context so committer continues even if workers fail
			if err := s.ds.Save(ctx, batch); err != nil {
				errCh <- err
				return
			}
		}
	}()

	g, workerCtx := errgroup.WithContext(ctx)
	for i := 0; i < s.workers; i++ {
		workerID := i + 1
		g.Go(func() error {
			var workerErrors []error
			processedDays := 0
			failedDays := 0

			for day := range workCh {
				processedDays++
				if err := s.syncDay(workerCtx, day, commitCh); err != nil {
					failedDays++
					workerErrors = append(workerErrors, fmt.Errorf("day %s: %w", day, err))

					continue
				}
			}

			if len(workerErrors) > 0 && failedDays == processedDays {
				return fmt.Errorf("worker #%d failed all %d days: %v", workerID, processedDays, workerErrors)
			}

			return nil
		})
	}

	workerErr := g.Wait()
	if workerErr != nil {
		slog.Error("Workers encountered errors", "processID", processID, "error", workerErr)
	}
	close(commitCh)

	committerWG.Wait()

	select {
	case err := <-errCh:
		return fmt.Errorf("committer error: %w", err)
	default:
	}

	if workerErr != nil {
		return fmt.Errorf("worker errors occurred: %w", workerErr)
	}

	slog.Info("CloudTrail sync finished")
	return nil
}

// ---------------------------------------------------------------------------
// DISCOVERY
// ---------------------------------------------------------------------------

// discoverAccountsAndRegions walks `AWSLogs/` and returns account→[]region map.
func (s *Syncer) discoverAccountsAndRegions(ctx context.Context) (map[string][]string, error) {
	slog.Info("Discovering accounts and regions")
	root := "AWSLogs/"
	out := map[string][]string{}

	it := s.prefixIter(ctx, root, "")
	for it.Next() {
		accountID := strings.TrimSuffix(strings.TrimPrefix(it.Prefix(), root), "/")
		regPath := path.Join(it.Prefix(), "CloudTrail") + "/"
		regIter := s.prefixIter(ctx, regPath, "")
		for regIter.Next() {
			region := strings.TrimSuffix(strings.TrimPrefix(regIter.Prefix(), regPath), "/")
			out[accountID] = append(out[accountID], region)
		}
		if err := regIter.Err(); err != nil {
			return nil, err
		}
	}
	return out, it.Err()
}

// enqueueAllDays emits one prefix per calendar-day into work chan.
func (s *Syncer) enqueueAllDays(ctx context.Context, acc map[string][]string, cutoff time.Time, work chan<- string) error {
	slog.Info("Enqueuing days", "accounts", acc)
	for acct, regions := range acc {
		for _, region := range regions {
			root := fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/", acct, region)
			yearIter := s.prefixIter(ctx, root, "")
			for yearIter.Next() {
				yr := yearIter.Suffix()

				yrInt, err := strconv.Atoi(yr[:4])
				if err != nil {
					return err
				}
				if yrInt < cutoff.Year() { // entire year older → stop
					continue
				}

				monthIter := s.prefixIter(ctx, root+yr, "")
				for monthIter.Next() {
					mo := monthIter.Suffix()

					moInt, err := strconv.Atoi(mo[:2])
					if err != nil {
						return err
					}
					if yrInt == cutoff.Year() && time.Month(moInt) < cutoff.Month() {
						continue
					}

					dayIter := s.prefixIter(ctx, root+yr+mo, "")
					for dayIter.Next() {

						day := dayIter.Suffix()
						prefix := root + yr + mo + day // yyyy/mm/dd/

						dayInt, err := strconv.Atoi(day[:2])
						if err != nil {
							return err
						}

						dayDate := time.Date(yrInt, time.Month(moInt), dayInt,
							0, 0, 0, 0, time.UTC)
						if dayDate.Before(cutoff) {
							continue
						}

						work <- prefix
					}
					if err := dayIter.Err(); err != nil {
						return err
					}
				}
				if err := monthIter.Err(); err != nil {
					return err
				}
			}
			if err := yearIter.Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

// prefixIter is a helper that yields "folders" one level below base.
type prefixIter struct {
	ctx    context.Context
	s3     *s3.Client
	bucket string
	base   string
	token  *string
	err    error
	cur    []string // batch of prefixes
	seen   map[string]bool
	i      int
}

func (s *Syncer) prefixIter(ctx context.Context, base, delim string) *prefixIter {
	if delim == "" {
		delim = "/"
	}
	return &prefixIter{ctx: ctx, s3: s.s3, bucket: s.bucket, base: base, seen: map[string]bool{}}
}
func (p *prefixIter) Next() bool {
	// load a page if we’ve exhausted the current slice
	for p.err == nil && p.i >= len(p.cur) {
		out, err := p.s3.ListObjectsV2(p.ctx, &s3.ListObjectsV2Input{
			Bucket:            &p.bucket,
			Prefix:            &p.base,
			Delimiter:         aws.String("/"),
			ContinuationToken: p.token,
		})
		if err != nil {
			p.err = err
			return false
		}

		// rebuild slice with unseen prefixes from this page
		p.cur = p.cur[:0]
		for _, cp := range out.CommonPrefixes {
			pfx := strings.TrimPrefix(*cp.Prefix, p.base)
			if !p.seen[pfx] {
				p.cur = append(p.cur, pfx)
				p.seen[pfx] = true
			}
		}
		p.i = 0                // reset index for new page
		if !*out.IsTruncated { // no more pages
			p.token = nil
		} else {
			p.token = out.NextContinuationToken
		}
		// if the current page had *no* new prefixes and there is no
		// next page, bail out
		if len(p.cur) == 0 && p.token == nil {
			return false
		}
	}

	// nothing left
	if p.err != nil || p.i >= len(p.cur) {
		return false
	}

	p.i++ // <-- advance cursor so the next call moves on
	return true
}

func (p *prefixIter) Prefix() string { return p.base + p.cur[p.i-1] }
func (p *prefixIter) Suffix() string { return p.cur[p.i-1] }
func (p *prefixIter) Err() error     { return p.err }
func (p *prefixIter) reset()         { p.i++ }

// ---------------------------------------------------------------------------
// PER-DAY PROCESSING
// ---------------------------------------------------------------------------

func (s *Syncer) syncDay(
	ctx context.Context,
	dayPrefix string,
	commitCh chan<- []ocsf.APIActivity) error {

	slog.Info("Syncing day", "dayPrefix", dayPrefix)

	it := s.objectIter(ctx, dayPrefix)
	buf := make([]ocsf.APIActivity, 0, s.batchSize)

	for it.Next() {
		key := it.Key()
		if !strings.HasSuffix(key, ".json.gz") {
			continue
		}

		if err := s.processFile(ctx, key, &buf); err != nil {
			return err
		}

		if len(buf) >= s.batchSize {
			out := make([]ocsf.APIActivity, len(buf))
			copy(out, buf)
			commitCh <- out
			buf = buf[:0]
		}
	}
	if err := it.Err(); err != nil {
		return err
	}

	if len(buf) > 0 {
		out := make([]ocsf.APIActivity, len(buf))
		copy(out, buf)
		commitCh <- out
	}
	return nil
}

// objectIter paginates all objects under prefix.
type objectIter struct {
	ctx    context.Context
	s3     *s3.Client
	bucket string
	prefix string
	token  *string
	cur    []string
	seen   map[string]bool
	i      int
	err    error
}

func (s *Syncer) objectIter(ctx context.Context, pfx string) *objectIter {
	return &objectIter{ctx: ctx, s3: s.s3, bucket: s.bucket, prefix: pfx, seen: map[string]bool{}}
}
func (o *objectIter) Next() bool {
	for o.err == nil && o.i >= len(o.cur) {
		out, err := o.s3.ListObjectsV2(o.ctx, &s3.ListObjectsV2Input{
			Bucket:            &o.bucket,
			Prefix:            &o.prefix,
			ContinuationToken: o.token,
		})
		if err != nil {
			o.err = err
			return false
		}
		o.cur = o.cur[:0]
		for _, obj := range out.Contents {
			if !o.seen[*obj.Key] {
				o.cur = append(o.cur, *obj.Key)
				o.seen[*obj.Key] = true
			}
		}
		o.i = 0
		if !*out.IsTruncated {
			o.token = nil
		} else {
			o.token = out.NextContinuationToken
		}
		if len(o.cur) == 0 && o.token == nil {
			return false
		}
	}
	if o.err != nil || o.i >= len(o.cur) {
		return false
	}

	o.i++
	return true
}
func (o *objectIter) Key() string { return o.cur[o.i-1] }
func (o *objectIter) Err() error  { return o.err }
func (o *objectIter) reset()      { o.i++ }

// ---------------------------------------------------------------------------
// FILE → OCSF CONVERSION
// ---------------------------------------------------------------------------

func (s *Syncer) processFile(ctx context.Context, key string, buf *[]ocsf.APIActivity) error {
	slog.Info("Processing file", "key", key)
	obj, err := s.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return oops.Wrapf(err, "get object")
	}
	defer obj.Body.Close()

	gzr, err := gzip.NewReader(obj.Body)
	if err != nil {
		return fmt.Errorf("gzip %s: %w", key, err)
	}
	defer gzr.Close()

	var file LogFile
	if err := json.NewDecoder(gzr).Decode(&file); err != nil && err != io.EOF {
		return fmt.Errorf("decode %s: %w", key, err)
	}

	for _, rec := range file.Records {
		evt, err := s.ToOCSF(ctx, rec)
		if err != nil {
			slog.Warn("convert", "key", key, "err", err)
			continue
		}
		*buf = append(*buf, evt)
	}
	return nil
}

func (s *Syncer) ToOCSF(ctx context.Context, event CloudtrailEvent) (ocsf.APIActivity, error) {
	// Parse the event data for OCSF conversion
	classUID := 6003
	categoryUID := 6
	categoryName := "Application Activity"
	className := "API Activity"

	var activityID int
	var activityName string
	var typeUID int
	var typeName string

	// Determine the activity type based on the event name
	eventName := event.EventName
	if strings.HasPrefix(eventName, "Create") || strings.HasPrefix(eventName, "Add") ||
		strings.HasPrefix(eventName, "Put") || strings.HasPrefix(eventName, "Insert") {
		activityID = 1
		activityName = "create"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Create"
	} else if strings.HasPrefix(eventName, "Get") || strings.HasPrefix(eventName, "Describe") ||
		strings.HasPrefix(eventName, "List") || strings.HasPrefix(eventName, "Search") {
		activityID = 2
		activityName = "read"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Read"
	} else if strings.HasPrefix(eventName, "Update") || strings.HasPrefix(eventName, "Modify") ||
		strings.HasPrefix(eventName, "Set") {
		activityID = 3
		activityName = "update"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Update"
	} else if strings.HasPrefix(eventName, "Delete") || strings.HasPrefix(eventName, "Remove") {
		activityID = 4
		activityName = "delete"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Delete"
	} else {
		activityID = 0
		activityName = "unknown"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Unknown"
	}

	// Map event success to OCSF status
	status := "unknown"
	statusID := 0
	// TODO: each response type is different depending on the event source

	if event.ErrorCode == nil || *event.ErrorCode == "" {
		status = "success"
		statusID = 1
	} else {
		status = "failure"
		statusID = 2
	}

	// Set severity based on error information
	severity := "informational"
	severityID := 1
	if event.ErrorCode != nil {
		severity = "medium"
		severityID = 3
	}

	// Parse actor information
	var actor ocsf.Actor
	if event.UserIdentity.UserName != nil && *event.UserIdentity.UserName != "" {
		actor = ocsf.Actor{
			AppName: stringPtr(event.EventSource),
			User: &ocsf.User{
				Uid:  stringPtr(*event.UserIdentity.UserName),
				Name: stringPtr(*event.UserIdentity.UserName),
			},
		}
		acctID := event.UserIdentity.AccountID
		if acctID != nil {
			actor.User.Account = &ocsf.Account{
				TypeId: int32Ptr(10), // AWS Account
				Type:   stringPtr("AWS Account"),
				Uid:    stringPtr(*event.UserIdentity.AccountID),
			}
		}
	} else {
		actor = ocsf.Actor{
			AppName: stringPtr(event.EventSource),
		}
	}

	// Parse API information
	api := ocsf.API{
		Operation: event.EventName,
		Service: &ocsf.Service{
			Name: stringPtr(event.EventSource),
		},
	}

	// Parse resource information
	var resources []ocsf.ResourceDetails
	if event.Resources != nil {
		for _, resource := range event.Resources {
			resources = append(resources, ocsf.ResourceDetails{
				Name: stringPtr(resource.ARN),
				Type: stringPtr(resource.Type),
				Uid:  stringPtr(resource.ARN),
			})
		}
	}

	// Parse source endpoint information
	var srcEndpoint ocsf.NetworkEndpoint
	if event.SourceIP != "" {
		srcEndpoint = ocsf.NetworkEndpoint{
			Ip: stringPtr(event.SourceIP),
		}
	} else {
		srcEndpoint = ocsf.NetworkEndpoint{
			SvcName: stringPtr(event.EventSource),
		}
	}

	// Parse timestamp
	var ts time.Time
	if !event.EventTime.IsZero() {
		ts = event.EventTime
	} else {
		ts = time.Now()
	}

	// Create the OCSF API Activity
	activity := ocsf.APIActivity{
		ActivityId:   int32(activityID),
		ActivityName: &activityName,
		Actor:        actor,
		Api:          api,
		CategoryName: &categoryName,
		CategoryUid:  int32(categoryUID),
		ClassName:    &className,
		ClassUid:     int32(classUID),
		Status:       &status,
		StatusId:     int32Ptr(int32(statusID)),
		Cloud: ocsf.Cloud{
			Provider: "AWS",
			Region:   stringPtr(event.AwsRegion),
			Account: &ocsf.Account{
				TypeId: int32Ptr(10), // AWS Account
				Type:   stringPtr("AWS Account"),
				Uid:    stringPtr(event.RecipientAccountID),
			},
		},

		Resources:  resources,
		Severity:   &severity,
		SeverityId: int32(severityID),

		Metadata: ocsf.Metadata{
			CorrelationUid: stringPtr(event.EventID),
		},

		SrcEndpoint:    srcEndpoint,
		Time:           ts.UnixMilli(),
		TypeName:       &typeName,
		TypeUid:        int64(typeUID),
		TimezoneOffset: int32Ptr(0),
	}

	return activity, nil
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

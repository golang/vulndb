package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/vulndb/osv"
)

type dbIndex struct{}

type source interface {
	Get([]string) ([]*osv.Entry, error)
	Index() (map[string]time.Time, error)
}

type localSource struct {
	dir string
}

func (ls *localSource) Get(packages []string) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	for _, p := range packages {
		content, err := os.ReadFile(filepath.Join(ls.dir, p+".json"))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		var e []*osv.Entry
		if err = json.Unmarshal(content, &e); err != nil {
			return nil, err
		}
		entries = append(entries, e...)
	}
	return entries, nil
}

func (ls *localSource) Index() (map[string]time.Time, error) {
	var index map[string]time.Time
	b, err := os.ReadFile(filepath.Join(ls.dir, "index.json"))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &index); err != nil {
		return nil, err
	}
	return index, nil
}

type httpSource struct {
	url    string
	c      *http.Client
	cache  Cache
	dbName string
}

func (hs *httpSource) Index() (map[string]time.Time, error) {
	var cachedIndex map[string]time.Time
	var cachedIndexRetrieved *time.Time

	if hs.cache != nil {
		cachedIndex, retrieved, err := hs.cache.ReadIndex(hs.dbName)
		if err != nil {
			return nil, err
		}

		if cachedIndex != nil {
			if time.Since(retrieved) < time.Hour*2 {
				return cachedIndex, nil
			}

			cachedIndexRetrieved = &retrieved
		}
	}

	req, err := http.NewRequest("GET", path.Join(hs.url, "index.json"), nil)
	if err != nil {
		return nil, err
	}
	if cachedIndexRetrieved != nil {
		req.Header.Add("If-Modified-Since", cachedIndexRetrieved.Format(http.TimeFormat))
	}
	resp, err := hs.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if cachedIndexRetrieved != nil && resp.StatusCode == http.StatusNotModified {
		return cachedIndex, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var index map[string]time.Time
	if err = json.Unmarshal(b, &index); err != nil {
		return nil, err
	}

	if hs.cache != nil {
		if err = hs.cache.WriteIndex(hs.dbName, index, time.Now()); err != nil {
			return nil, err
		}
	}

	return index, nil
}

func (hs *httpSource) Get(packages []string) ([]*osv.Entry, error) {
	var entries []*osv.Entry

	index, err := hs.Index()
	if err != nil {
		return nil, err
	}

	var stillNeed []string
	if hs.cache != nil {
		for _, p := range packages {
			lastModified, present := index[p]
			if !present {
				continue
			}
			if cached, err := hs.cache.ReadEntries(hs.dbName, p); err != nil {
				return nil, err
			} else if cached != nil {
				var stale bool
				for _, e := range entries {
					if e.LastModified.Before(lastModified) {
						stale = true
						break
					}
				}
				if !stale {
					entries = append(entries, cached...)
					continue
				}
			}
			stillNeed = append(stillNeed, p)
		}
	} else {
		stillNeed = packages
	}

	for _, p := range stillNeed {
		resp, err := hs.c.Get(path.Join(hs.url, p+".json"))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		// might want this to be a LimitedReader
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var e []*osv.Entry
		if err = json.Unmarshal(content, &e); err != nil {
			return nil, err
		}
		// TODO: we may want to check that the returned entries actually match
		// the package we asked about, so that the cache cannot be poisoned
		entries = append(entries, e...)

		if hs.cache != nil {
			if err := hs.cache.WriteEntries(hs.dbName, p, e); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

type Client struct {
	sources []source
}

type Options struct {
	HTTPClient *http.Client
	HTTPCache  Cache
}

func NewClient(sources []string, opts Options) (*Client, error) {
	c := &Client{}
	for _, uri := range sources {
		// should parse the URI out here instead of in there
		switch {
		case strings.HasPrefix("http://", uri) || strings.HasPrefix("https://", uri):
			hs := &httpSource{url: uri}
			url, err := url.Parse(uri)
			if err != nil {
				return nil, err
			}
			hs.dbName = url.Hostname()
			if opts.HTTPCache != nil {
				hs.cache = opts.HTTPCache
			}
			if opts.HTTPClient != nil {
				hs.c = opts.HTTPClient
			} else {
				hs.c = new(http.Client)
			}
			c.sources = append(c.sources, hs)
		case strings.HasPrefix("file://", uri):
			url, err := url.Parse(uri)
			if err != nil {
				return nil, err
			}
			c.sources = append(c.sources, &localSource{dir: url.Path})
		default:
			return nil, fmt.Errorf("source %q has unsupported scheme", uri)
		}
	}
	return c, nil
}

func (c *Client) Get(packages []string) ([]*osv.Entry, error) {
	var entries []*osv.Entry
	// probably should be parallelized
	for _, s := range c.sources {
		e, err := s.Get(packages)
		if err != nil {
			return nil, err // be failure tolerant?
		}
		entries = append(entries, e...)
	}
	return entries, nil
}

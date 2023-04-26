package updater

import (
	"sync"
	"time"
)

var metadataFetchers = make(map[string]MetadataFetcher)

type VulnerabilityWithLock struct {
	*Vulnerability
	Lock sync.Mutex
}

// MetadataFetcher 定义了元数据获取器的接口
type MetadataFetcher interface {

	// Load 在 Updater 调用每个漏洞的 AddMetadata 之前运行。
	Load(Datastore) error

	// AddMetadata 向给定的 database.Vulnerability 添加元数据。
	// 预期该获取器在操作 Metadata map 时使用 .Lock.Lock() 进行加锁。
	AddMetadata(*VulnerabilityWithLock) error

	LookupMetadata(name string) (string, float64, string, float64, bool)
	AddAffectedVersion(name string) ([]string, []string, bool)
	AddCveDate(name string) (time.Time, time.Time, bool)

	// Unload 在 Updater 调用完所有漏洞的 AddMetadata 后运行。
	Unload()

	// Clean 在 Clair 停止时删除任何已分配的资源。
	Clean()
}

// RegisterFetcher 通过提供的名称将 Fetcher 注册为可用的获取器。
// 如果使用相同的名称多次调用 Register，或者驱动程序为 nil，则会引发 panic。
func RegisterMetadataFetcher(name string, f MetadataFetcher) {
	if name == "" {
		panic("updater: could not register a MetadataFetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil MetadataFetcher")
	}

	if _, dup := fetchers[name]; dup {
		panic("updater: RegisterMetadataFetcher called twice for " + name)
	}

	metadataFetchers[name] = f
}

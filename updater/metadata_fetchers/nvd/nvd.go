// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qiniu/qmgo"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater"
)

const (
	jsonUrl      = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

	metadataKey string = "NVD"
	retryTimes         = 5
	timeFormat         = "2006-01-02T15:04Z"
)

type NVDMetadataFetcher struct {
	localPath string
	lock      sync.Mutex

	metadata map[string]common.NVDMetadata
}

type NvdCve struct {
	Cve struct {
		DataType    string `json:"data_type"`
		DataFormat  string `json:"data_format"`
		DataVersion string `json:"data_version"`
		CVEDataMeta struct {
			ID       string `json:"ID"`
			ASSIGNER string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		Affects struct {
			Vendor struct {
				VendorData []struct {
					VendorName string `json:"vendor_name"`
					Product    struct {
						ProductData []struct {
							ProductName string `json:"product_name"`
							Version     struct {
								VersionData []struct {
									VersionValue    string `json:"version_value"`
									VersionAffected string `json:"version_affected"`
								} `json:"version_data"`
							} `json:"version"`
						} `json:"product_data"`
					} `json:"product"`
				} `json:"vendor_data"`
			} `json:"vendor"`
		} `json:"affects"`
		Problemtype struct {
			ProblemtypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				URL       string        `json:"url"`
				Name      string        `json:"name"`
				Refsource string        `json:"refsource"`
				Tags      []interface{} `json:"tags"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []struct {
			Operator string `json:"operator"`
			CpeMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Cpe23URI              string `json:"cpe23Uri"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CvssV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
		BaseMetricV2 struct {
			CvssV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

type NvdData struct {
	CVEDataType         string   `json:"CVE_data_type"`
	CVEDataFormat       string   `json:"CVE_data_format"`
	CVEDataVersion      string   `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string   `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string   `json:"CVE_data_timestamp"`
	CVEItems            []NvdCve `json:"CVE_Items"`
}

type cveMitre struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		State             string `json:"state"`
		CveID             string `json:"cveId"`
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		DateUpdated       string `json:"dateUpdated"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			ProviderMetadata struct {
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				} `json:"versions"`
			} `json:"affected"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Source struct {
				Discovery string `json:"discovery"`
			} `json:"source"`
		} `json:"cna"`
	} `json:"containers"`
}

var url = "mongodb://10.0.0.8:27017"
var database = "cvelist"
var collection = "cve"
var cli *qmgo.QmgoClient
var ctx context.Context

// 获取mongo数据库连接
func GetDbClient() {
	ctx = context.Background()
	c, err := qmgo.Open(ctx, &qmgo.Config{Uri: url, Database: database, Coll: collection})
	if err != nil {
		log.Fatalln("err")
	}
	cli = c
}

func init() {
	updater.RegisterMetadataFetcher("NVD", &NVDMetadataFetcher{})
	GetDbClient()

}

func (fetcher *NVDMetadataFetcher) Load(datastore updater.Datastore) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	var err error
	fetcher.metadata = make(map[string]common.NVDMetadata)

	// Init if necessary.
	if fetcher.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if fetcher.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return common.ErrFilesystem
		}
	}
	defer os.RemoveAll(fetcher.localPath)

	// Get data feeds.
	for y := common.FirstYear; y <= time.Now().Year(); y++ {
		dataFeedName := strconv.Itoa(y)

		retry := 0
		for retry <= retryTimes {
			// json
			r, err := http.Get(fmt.Sprintf(jsonUrl, dataFeedName))
			if err != nil {
				if retry == retryTimes {
					log.Errorf("Failed to download NVD data feed file '%s': %s", dataFeedName, err)
					return common.ErrCouldNotDownload
				}
				retry++
				log.WithFields(log.Fields{"error": err, "retry": retry}).Debug("Failed to get NVD data")
				continue
			}

			// Un-gzip it.
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				if retry == retryTimes {
					log.Errorf("Failed to read NVD data feed file '%s': %s", dataFeedName, err)
					return common.ErrCouldNotDownload
				}
				retry++
				log.WithFields(log.Fields{"error": err, "retry": retry}).Debug("Failed to ungzip NVD data")
				continue
			}
			jsonData := utils.GunzipBytes(body)

			var nvdData NvdData
			err = json.Unmarshal(jsonData, &nvdData)
			if err != nil {
				log.Errorf("Failed to unmarshal NVD data feed file '%s': %s", dataFeedName, err)
				return common.ErrCouldNotDownload
			}
			for _, cve := range nvdData.CVEItems {
				var meta common.NVDMetadata
				if len(cve.Cve.Description.DescriptionData) > 0 {
					meta.Description = cve.Cve.Description.DescriptionData[0].Value
				}
				if cve.Cve.CVEDataMeta.ID != "" {
					if cve.Impact.BaseMetricV3.CvssV3.BaseScore != 0 {
						meta.CVSSv3.Vectors = cve.Impact.BaseMetricV3.CvssV3.VectorString
						meta.CVSSv3.Score = cve.Impact.BaseMetricV3.CvssV3.BaseScore
					}
					if cve.Impact.BaseMetricV2.CvssV2.BaseScore != 0 {
						meta.CVSSv2.Vectors = cve.Impact.BaseMetricV2.CvssV2.VectorString
						meta.CVSSv2.Score = cve.Impact.BaseMetricV2.CvssV2.BaseScore
					}
					if cve.PublishedDate != "" {
						if t, err := time.Parse(timeFormat, cve.PublishedDate); err == nil {
							meta.PublishedDate = t
						}
					}
					if cve.LastModifiedDate != "" {
						if t, err := time.Parse(timeFormat, cve.LastModifiedDate); err == nil {
							meta.LastModifiedDate = t
						}
					}

					meta.VulnVersions = make([]common.NVDvulnerableVersion, 0)
					for _, node := range cve.Configurations.Nodes {
						if node.Operator == "OR" && len(node.CpeMatch) > 0 {
							for _, m := range node.CpeMatch {
								if m.Vulnerable &&
									// TODO: explicitly ignore microsoft:visual_studio_, as it is often confused with .net core version
									!strings.Contains(m.Cpe23URI, "microsoft:visual_studio_") &&
									(m.VersionStartIncluding != "" ||
										m.VersionStartExcluding != "" ||
										m.VersionEndIncluding != "" ||
										m.VersionEndExcluding != "") {
									meta.VulnVersions = append(meta.VulnVersions, common.NVDvulnerableVersion{
										StartIncluding: m.VersionStartIncluding,
										StartExcluding: m.VersionStartExcluding,
										EndIncluding:   m.VersionEndIncluding,
										EndExcluding:   m.VersionEndExcluding,
									})
								}
							}
						}
					}

					fetcher.metadata[cve.Cve.CVEDataMeta.ID] = meta

					// log.WithFields(log.Fields{"cve": cve.Cve.CVEDataMeta.ID, "v3": meta.CVSSv3.Score}).Info()
				}
			}

			log.WithFields(log.Fields{"year": dataFeedName, "count": len(nvdData.CVEItems)}).Info()
			break
		}
	}

	return nil
}
func (fetcher *NVDMetadataFetcher) LoadFromfile(datastore updater.Datastore) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	var err error
	fetcher.metadata = make(map[string]common.NVDMetadata)

	// Init if necessary.
	if fetcher.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if fetcher.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return common.ErrFilesystem
		}
	}
	defer os.RemoveAll(fetcher.localPath)

	// Get data feeds.
	for y := common.FirstYear; y <= time.Now().Year(); y++ {
		dataFeedName := strconv.Itoa(y)

		// json
		//r, err := http.Get(fmt.Sprintf(jsonUrl, dataFeedName))
		f, err := os.Open("nvdcve-1.1-" + dataFeedName + ".json.gz")
		if err != nil {
			log.Println("file open error:", err)
		}
		// Un-gzip it.
		body, err := ioutil.ReadAll(f)
		if err != nil {
			log.Println("readall  error:", err)
		}
		jsonData := utils.GunzipBytes(body)

		var nvdData NvdData
		err = json.Unmarshal(jsonData, &nvdData)
		if err != nil {
			log.Errorf("Failed to unmarshal NVD data feed file '%s': %s", dataFeedName, err)
			return common.ErrCouldNotDownload
		}
		for _, cve := range nvdData.CVEItems {
			var meta common.NVDMetadata
			if len(cve.Cve.Description.DescriptionData) > 0 {
				meta.Description = cve.Cve.Description.DescriptionData[0].Value
			}
			if cve.Cve.CVEDataMeta.ID != "" {
				if cve.Impact.BaseMetricV3.CvssV3.BaseScore != 0 {
					meta.CVSSv3.Vectors = cve.Impact.BaseMetricV3.CvssV3.VectorString
					meta.CVSSv3.Score = cve.Impact.BaseMetricV3.CvssV3.BaseScore
				}
				if cve.Impact.BaseMetricV2.CvssV2.BaseScore != 0 {
					meta.CVSSv2.Vectors = cve.Impact.BaseMetricV2.CvssV2.VectorString
					meta.CVSSv2.Score = cve.Impact.BaseMetricV2.CvssV2.BaseScore
				}
				if cve.PublishedDate != "" {
					if t, err := time.Parse(timeFormat, cve.PublishedDate); err == nil {
						meta.PublishedDate = t
					}
				}
				if cve.LastModifiedDate != "" {
					if t, err := time.Parse(timeFormat, cve.LastModifiedDate); err == nil {
						meta.LastModifiedDate = t
					}
				}

				meta.VulnVersions = make([]common.NVDvulnerableVersion, 0)
				for _, node := range cve.Configurations.Nodes {
					if node.Operator == "OR" && len(node.CpeMatch) > 0 {
						for _, m := range node.CpeMatch {
							if m.Vulnerable &&
								// TODO: explicitly ignore microsoft:visual_studio_, as it is often confused with .net core version
								!strings.Contains(m.Cpe23URI, "microsoft:visual_studio_") &&
								(m.VersionStartIncluding != "" ||
									m.VersionStartExcluding != "" ||
									m.VersionEndIncluding != "" ||
									m.VersionEndExcluding != "") {
								meta.VulnVersions = append(meta.VulnVersions, common.NVDvulnerableVersion{
									StartIncluding: m.VersionStartIncluding,
									StartExcluding: m.VersionStartExcluding,
									EndIncluding:   m.VersionEndIncluding,
									EndExcluding:   m.VersionEndExcluding,
								})
							}
						}
					}
				}

				fetcher.metadata[cve.Cve.CVEDataMeta.ID] = meta

				// log.WithFields(log.Fields{"cve": cve.Cve.CVEDataMeta.ID, "v3": meta.CVSSv3.Score}).Info()

			}

			log.WithFields(log.Fields{"year": dataFeedName, "count": len(nvdData.CVEItems)}).Info()
			break
		}
	}

	return nil
}

var redhatCveRegexp = regexp.MustCompile(`\(CVE-([0-9]+)-([0-9]+)`)

func (fetcher *NVDMetadataFetcher) AddMetadata(v *updater.VulnerabilityWithLock) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	cves := []updater.CVE{updater.CVE{Name: v.Name}}
	if len(v.CVEs) > 0 {
		cves = v.CVEs
	}

	var maxV2, maxV3 float64
	var found bool

	v.Lock.Lock()
	defer v.Lock.Unlock()
	for _, cve := range cves {
		nvd, ok := fetcher.metadata[cve.Name]
		if !ok {
			nvd = common.NVDMetadata{
				CVSSv2:           common.CVSS{Vectors: cve.CVSSv2.Vectors, Score: cve.CVSSv2.Score},
				CVSSv3:           common.CVSS{Vectors: cve.CVSSv3.Vectors, Score: cve.CVSSv3.Score},
				PublishedDate:    v.Vulnerability.IssuedDate,
				LastModifiedDate: v.Vulnerability.LastModDate,
			}
		} else {
			found = true
		}

		// Create Metadata map if necessary.
		if v.Metadata == nil {
			v.Metadata = make(map[string]interface{})
		}

		if v.Vulnerability.Description == "" {
			if nvd.Description == "" {
				v.Vulnerability.Description = getCveDescriptionFromDB(v.Vulnerability.Name)
			} else {
				v.Vulnerability.Description = nvd.Description
			}
		}

		// Redhat and Amazon fetcher retrieves issued date
		if v.Vulnerability.IssuedDate.IsZero() {
			v.Vulnerability.IssuedDate = nvd.PublishedDate
		}
		if v.Vulnerability.LastModDate.IsZero() {
			v.Vulnerability.LastModDate = nvd.LastModifiedDate
		}

		if nvd.CVSSv3.Score > maxV3 {
			maxV3 = nvd.CVSSv3.Score
			maxV2 = nvd.CVSSv2.Score
			v.Metadata[metadataKey] = nvd
			continue
		} else if nvd.CVSSv3.Score < maxV3 {
			continue
		}
		if nvd.CVSSv2.Score > maxV2 {
			maxV3 = nvd.CVSSv3.Score
			maxV2 = nvd.CVSSv2.Score
			v.Metadata[metadataKey] = nvd
		}
	}

	// if v.Vulnerability.Name == "CVE-2021-3426" {
	// 	log.WithFields(log.Fields{"v": v.Vulnerability}).Error("================")
	// }

	if found && (maxV3 > 0 || maxV2 > 0) {
		// log.WithFields(log.Fields{"cve": v.Name, "maxV2": maxV2, "maxV3": maxV3}).Info()

		// For NVSHAS-4709, always set the severity by CVSS scores
		// if v.Vulnerability.Severity == common.Unknown || v.Vulnerability.Severity == "" {
		// similar logic in app fetchers
		if maxV3 >= 7 || maxV2 >= 7 {
			v.Vulnerability.Severity = common.High
		} else if maxV3 >= 4 || maxV2 >= 4 {
			v.Vulnerability.Severity = common.Medium
		} else {
			v.Vulnerability.Severity = common.Low
		}
	} else {
		if v.Vulnerability.Description == "" {
			v.Vulnerability.Description = getCveDescriptionFromDB(v.Vulnerability.Name)
		}
	}
	return nil
}

// 返回 CVE 的发布日期和最后修改日期
func (fetcher *NVDMetadataFetcher) AddCveDate(name string) (time.Time, time.Time, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok { // 检查给定的 name 是否存在于 metadata 中
		return nvd.PublishedDate, nvd.LastModifiedDate, true // 返回 CVE 的发布日期和最后修改日期以及 true 表示存在
	}

	return time.Time{}, time.Time{}, false // 如果不存在则返回零值时间和 false 表示不存在
}

// 返回受影响版本和修复版本
func (fetcher *NVDMetadataFetcher) AddAffectedVersion(name string) ([]string, []string, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok { // 检查给定的 name 是否存在于 metadata 中
		affects := make([]string, 0)
		fixes := make([]string, 0)
		opAffect := ""
		opFix := ""
		for _, v := range nvd.VulnVersions { // 遍历受影响版本信息
			if v.StartIncluding != "" {
				affects = append(affects, fmt.Sprintf("%s>=%s", opAffect, v.StartIncluding))
				opAffect = ""
			} else if v.StartExcluding != "" {
				affects = append(affects, fmt.Sprintf("%s>%s", opAffect, v.StartExcluding))
				opAffect = ""
			}
			if v.EndIncluding != "" {
				affects = append(affects, fmt.Sprintf("%s<=%s", opAffect, v.EndIncluding))
				fixes = append(fixes, fmt.Sprintf("%s>%s", opFix, v.EndIncluding))
			} else if v.EndExcluding != "" {
				affects = append(affects, fmt.Sprintf("%s<%s", opAffect, v.EndExcluding))
				fixes = append(fixes, fmt.Sprintf("%s>=%s", opFix, v.EndExcluding))
			}
			opAffect = "||"
			opFix = "||"
		}
		return affects, fixes, true // 返回受影响版本和修复版本信息以及 true 表示存在
	}

	return nil, nil, false // 如果不存在则返回空切片和 false 表示不存在
}

func (fetcher *NVDMetadataFetcher) LookupMetadata(name string) (string, float64, string, float64, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok { // 检查给定的 name 是否存在于 metadata 中
		return nvd.CVSSv2.Vectors, nvd.CVSSv2.Score, nvd.CVSSv3.Vectors, nvd.CVSSv3.Score, true
	}

	return "", 0, "", 0, false
}

func (fetcher *NVDMetadataFetcher) Unload() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	fetcher.metadata = nil
	os.RemoveAll(fetcher.localPath)
}

func (fetcher *NVDMetadataFetcher) Clean() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	os.RemoveAll(fetcher.localPath)
}

func getHashFromMetaURL(metaURL string) (string, error) {
	r, err := http.Get(metaURL) // 发送 HTTP 请求获取 metaURL 对应的网页内容
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	scanner := bufio.NewScanner(r.Body) // 使用 bufio 包的 Scanner 进行逐行扫描网页内容
	for scanner.Scan() {
		line := scanner.Text()                  // 获取当前行的文本内容
		if strings.HasPrefix(line, "sha256:") { // 判断是否以 "sha256:" 开头
			return strings.TrimPrefix(line, "sha256:"), nil // 提取哈希值并去除前缀 "sha256:"，返回哈希值和 nil 错误
		}
	}
	if err := scanner.Err(); err != nil { // 检查 Scanner 是否出错
		return "", err
	}

	return "", errors.New("invalid .meta file format") // 返回自定义错误信息，表示 .meta 文件格式无效
}

// 获取给定 CVE 编号对应的描述信息
func getCveDescription(cve string) string {
	var description string
	url := cveURLPrefix + cve // 构建 CVE 信息的 URL
	r, err := http.Get(url)   // 发送 HTTP 请求获取网页内容
	if err != nil {
		log.WithFields(log.Fields{"cve": cve}).Error("no nvd data") // 记录错误日志：无法获取 CVE 数据
		return description                                          // 返回空的描述信息
	}
	defer r.Body.Close()

	var descEnable, descStart bool      // 描述信息使能标志和起始标志
	scanner := bufio.NewScanner(r.Body) // 使用 bufio 包的 Scanner 进行逐行扫描网页内容
	for scanner.Scan() {
		line := scanner.Text() // 获取当前行的文本内容
		if descEnable {
			if strings.Contains(line, "<td colspan=") { // 根据 HTML 标签特征，判断是否是描述信息的起始行
				descStart = true
			}
			if descStart && !strings.Contains(line, "<A HREF=") { // 判断是否是描述信息的结束行
				if i := strings.Index(line, "\">"); i > 0 { // 提取描述信息，并去除 HTML 标签
					description += line[i+2:]
				} else if strings.Contains(line, "</td>") { // 如果是描述信息的结束行，则直接返回当前描述信息
					return description
				} else {
					description += line // 将当前行添加到描述信息中
				}
				if len(description) > 0 && description[len(description)-1] != '.' { // 在描述信息末尾添加空格，除非已经以句号结尾
					description += " "
				}
			}
		}
		if strings.Contains(line, ">Description</th>") { // 根据 HTML 标签特征，判断是否是描述信息所在行
			descEnable = true // 设置描述信息使能标志
		}
	}
	return description // 返回最终的 CVE 描述信息
}

func getCveDescriptionFromDB(cve string) string {

	one := cveMitre{}
	err := cli.Find(context.Background(), bson.M{"cveMetadata.cveId": cve}).One(&one)
	if err != nil {
		log.Println("err", err)
		return "Descrrption not found "
	}
	if len(one.Containers.Cna.Descriptions) > 0 {
		return one.Containers.Cna.Descriptions[0].Value
	} else {
		return "Descrrption not found "
	}

}

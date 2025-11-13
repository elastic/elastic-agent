module github.com/elastic/elastic-agent/internal/edot

go 1.24.10

replace github.com/elastic/elastic-agent => ../../

replace (
	github.com/dop251/goja_nodejs => github.com/dop251/goja_nodejs v0.0.0-20171011081505-adff31b136e6
	// openshift removed all tags from their repo, use the pseudoversion from the release-3.9 branch HEAD
	// See https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/12d41f40b0d408b0167633d8095160d3343d46ac/go.mod#L38
	github.com/openshift/api v3.9.0+incompatible => github.com/openshift/api v0.0.0-20180801171038-322a19404e37
)

// Replace statements carried forward from Beats https://github.com/elastic/beats/blob/0678f4d96212ac968fc90596e60475ed2f3979e1/go.mod#L503
replace (
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/consumption/armconsumption => github.com/elastic/azure-sdk-for-go/sdk/resourcemanager/consumption/armconsumption v1.1.0-elastic
	github.com/apoydence/eachers => github.com/poy/eachers v0.0.0-20181020210610-23942921fe77 //indirect, see https://github.com/elastic/beats/pull/29780 for details.
	github.com/dop251/goja => github.com/elastic/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
	github.com/fsnotify/fsnotify => github.com/elastic/fsnotify v1.6.1-0.20240920222514-49f82bdbc9e3
	github.com/google/gopacket => github.com/elastic/gopacket v1.1.20-0.20241002174017-e8c5fda595e6
	github.com/insomniacslk/dhcp => github.com/elastic/dhcp v0.0.0-20200227161230-57ec251c7eb3 // indirect
	github.com/meraki/dashboard-api-go/v3 => github.com/tommyers-elastic/dashboard-api-go/v3 v3.0.0-20250616163611-a325b49669a4
)

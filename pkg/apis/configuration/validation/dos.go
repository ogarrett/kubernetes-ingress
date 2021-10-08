package validation

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var appProtectDosPolicyRequiredFields = [][]string{
	{"spec"},
}

var appProtectDosLogConfRequiredFields = [][]string{
	{"spec", "content"},
	{"spec", "filter"},
}

const MaxNameLength = 63

// ValidateAppProtectDosLogConf validates LogConfiguration resource
func ValidateAppProtectDosLogConf(logConf *unstructured.Unstructured) error {
	lcName := logConf.GetName()
	err := ValidateRequiredFields(logConf, appProtectDosLogConfRequiredFields)
	if err != nil {
		return fmt.Errorf("Error validating App Protect Dos Log Configuration %v: %w", lcName, err)
	}

	return nil
}

var (
	dosLogDstEx = regexp.MustCompile(`(\S+:\d{1,5})|stderr`)
)

// ValidateAppProtectDosLogDest validates destination for log configuration
func ValidateAppProtectDosLogDest(dstAntn string) error {
	errormsg := "Error parsing App Protect Log config: Destination must follow format: <ip-address | localhost | dns name>:<port> or stderr"
	if !dosLogDstEx.MatchString(dstAntn) {
		return fmt.Errorf("%s Log Destination did not follow format", errormsg)
	}
	if dstAntn == "stderr" {
		return nil
	}

	dstchunks := strings.Split(dstAntn, ":")

	// // This error can be ignored since the regex check ensures this string will be parsable
	port, _ := strconv.Atoi(dstchunks[1])
	if port > 65535 || port < 1 {
		return fmt.Errorf("error parsing port: %v not a valid port number", port)
	}

	return nil
}

// ValidateAppProtectDosName validates name of App Protect Dos
func ValidateAppProtectDosName(name string) error {
	if len(name) > MaxNameLength {
		return fmt.Errorf("App Protect Dos Name max length is %v", MaxNameLength)
	}

	return nil
}

// ValidateAppProtectDosMonitor validates monitor value of App Protect Dos
func ValidateAppProtectDosMonitor(monitor string) error {
	_, err := url.Parse(monitor)
	if err != nil {
		return fmt.Errorf("App Protect Dos Monitor must have valid URL")
	}

	return nil
}

// ValidateAppProtectDosPolicy validates Policy resource
func ValidateAppProtectDosPolicy(policy *unstructured.Unstructured) error {
	polName := policy.GetName()

	err := ValidateRequiredFields(policy, appProtectDosPolicyRequiredFields)
	if err != nil {
		return fmt.Errorf("Error validating App Protect Dos Policy %v: %w", polName, err)
	}

	return nil
}

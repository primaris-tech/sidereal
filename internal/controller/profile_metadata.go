package controller

import (
	"crypto/sha256"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ProbeProfileAnnotation preserves the full profile identifier on probe Jobs.
const ProbeProfileAnnotation = "sidereal.cloud/probe-profile"

// ProbeProfileLabelValue keeps existing valid labels and hashes profiles that
// contain characters or lengths Kubernetes cannot accept in a label value.
func ProbeProfileLabelValue(profile string) string {
	if len(validation.IsValidLabelValue(profile)) == 0 {
		return profile
	}
	sum := sha256.Sum256([]byte(profile))
	return fmt.Sprintf("sha256-%x", sum[:28])
}

func profileFromJob(job *batchv1.Job) string {
	if profile := job.Annotations[ProbeProfileAnnotation]; profile != "" {
		return profile
	}
	// Jobs created before profile annotations were added carry the full
	// identifier in the label. Keep those executions readable during upgrades.
	return job.Labels[ProbeProfileLabel]
}

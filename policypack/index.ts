import * as gcp from "@pulumi/gcp";
import { PolicyPack, validateResourceOfType } from "@pulumi/policy";

new PolicyPack("lotctl-gcp", {
	policies: [
		{
			name: "bucket-must-have-owner-label",
			description: "Checks if a GCP bucket has an 'owner' label.",
			enforcementLevel: "mandatory",
			validateResource: validateResourceOfType(gcp.storage.Bucket, (bucket, args, reportViolation) => {
				if (!bucket.labels || !bucket.labels["owner"]) {
					reportViolation("Bucket must have an 'owner' label.");
				}
			}),
		},
		{
			name: "detect-iam-binding",
			description: "Detects any IAM Binding resources.",
			enforcementLevel: "advisory",
			validateResource: (args, reportViolation) => {
				if (args.type.includes("IAMBinding")) {
					reportViolation("IAM Binding detected.");
				}
			},
		},
	],
});
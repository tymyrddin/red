# Major providers

All major cloud providers (AWS, Google Cloud, Microsoft Azure, Alibaba, Oracle Cloud) require a credit card or
equivalent identity-bound payment before approving an account. They also operate abuse and law-enforcement teams
that respond to takedown requests quickly, which makes them a poor fit for any host the target ever sees.

The majors are still useful in two narrow cases:

* The engagement contract explicitly permits cloud-of-record infrastructure. Some red team scopes prefer this for
billing and audit trail reasons.
* The infrastructure is on the management side only and never reaches the target's network. Even then, the
billing identity is a permanent link.

For anything that talks to the target, prefer the [alternative providers](alt-providers.md) that accept anonymous
payments.

## Resources

* [AWS](https://aws.amazon.com/), and [what payment methods does AWS accept?](https://aws.amazon.com/premiumsupport/knowledge-center/accepted-payment-methods/)
* [Google Cloud](https://cloud.google.com/), and [payment options for your Google service](https://support.google.com/cloudidentity/answer/1230192?hl=en)
* [Microsoft Azure](https://azure.microsoft.com/) requires a credit card and phone verification.
* [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/) demands credit card verification at signup.

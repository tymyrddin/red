# Introduction

Properly implemented bounce servers create essential operational air gaps between management infrastructure and 
target-facing systems. These sanitised environments host provisioning tools and C2 management consoles while 
maintaining strict network isolation from active operations. Regular rotation of bounce infrastructure - 
ideally through fully automated deployment pipelines - minimizes forensic links between different operational 
phases and ensures no single component becomes a pivot point for defenders.

* Bouncing servers are used to host management tools like Terraform, Docker, and Ansible to support multiple attack infrastructures.
* Although the servers never interact with the target, they can be associated with those parts of our attack infrastructures that do.
* Virtual servers (VPS) can be hosted on one or many cloud providers spread across many geographical locations.

## How?

* [Major cloud providers](major-providers.md)  
* [Research anonymous payments](payments.md)
* [Alternative cloud providers](alt-providers.md)







Cloud recon runbooks
=====================

Step-by-step procedures for enumerating specific cloud surfaces. Each runbook covers one provider or
service type from identification through to a complete picture of what is accessible and how.

Run these after passive surface discovery has confirmed which providers are in scope. They are ordered
roughly by how often they produce results: object storage and identity enumeration first, because
misconfigured storage and open tenant enumeration are still consistently the most productive starting
points.

.. toctree::
   :maxdepth: 1
   :includehidden:

   s3-discovery.md
   azure-tenant.md
   gcp.md
   saas-mapping.md
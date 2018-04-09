pyquickca
=========

Quickly create a ca and issue certificates


usage
-----

```python
import pyquickca

pyquickca.new_client_cert(ca_cert_file="ca.crt", ca_key_file="ca.key", client_cert_file="client.crt", client_key_file="client.key", commonName="testname")
```

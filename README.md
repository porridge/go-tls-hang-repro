
# Repro

Try:

```
GOTOOLCHAIN=go1.23.4 go test -v -timeout 10s ./ -run TestReproduceTLSHang
GOTOOLCHAIN=go1.24rc1 go test -v -timeout 10s ./ -run TestReproduceTLSHang
```

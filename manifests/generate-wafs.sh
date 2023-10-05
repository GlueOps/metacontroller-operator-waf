#!/bin/bash

output_file="waf.yaml"

# Start from 3 as per your example
start=1
end=$((start + 2))

# Clear or create the output file
> $output_file

for i in $(seq $start $end); do
  #next=$((i+1))
  cat <<EOF >> $output_file
---
apiVersion: metacontroller.glueops.dev/v1alpha1
kind: WebApplicationFirewall
metadata:
  name: example$(printf "%s" $i)
  namespace: default
spec:
  domains:
    - '$i.aws-waf-testing.venkatamutyala.com'

EOF
done

echo "Resources have been written to $output_file"

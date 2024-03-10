```
export DEPLOYMENT=foo
export NAME=bar
export REGION=us-east-1
export IAM_USER=myiamusername
```

Create a cluster:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t cluster \
  -k 1.24 \
  --dry-run
```

Create a fargate profile:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t fargateprofile \
  -n $NAME \
  -N fargate-profile  \
  --dry-run
```

Create IAM Service Account with policy json file:
(Must have json file in 'iam-policies/$NAME-iam-policy.json)

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t iamserviceaccount \
  -n $NAME \
  -N kube-system \
  --dry-run
```

Create IAM Service Account with existing policy ARN:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t iamserviceaccount \
  -n $NAME \
  -N kube-system \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess\
  --dry-run
```

Create IAM user admin identity mapping:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t adminusermap \
  -n $IAM_USER \
  --dry-run
```

Create nodegroup:

````
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a create \
  -t nodegroup \
  -n $NAME \
  -i m6i.xlarge \
  -k 1.24 \
  -d 0 \
  -M 3 \
  -m 0 \
  --dry-run
```
````

Upgrade Cluster:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a upgrade \
  -t cluster \
  -k 1.24 \
  --new-version 1.25 \
  --dry-run
```

Upgrade nodgroup AMI:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a upgrade \
  -t nodegroupami \
  -n $NAME \
  -k 1.24 \
  --new-version 1.25 \
  --dry-run
```

Upgrade nodegroup:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a upgrade \
  -t nodegroup \
  -n $NAME \
  -k 1.24 \
  --new-version 1.25 \
  --dry-run
```

Upgrade cluster, nodegroups and nodegroup AMIs:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t nodegroup \
  -n $DEPLOYMENT \
  -k 1.26 \
  --dry-run
```

Delete nodegroup:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t nodegroup \
  -n $NAME \
  -k 1.26 \
  --dry-run
```

Delete fargate profile:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t fargateprofile \
  -n $NAME \
  --dry-run
```

Delete IAM service account:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t iamserviceaccount \
  -n $NAME \
  -N kube-system \
  --dry-run
```

Delete admin user map:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t adminusermap \
  -n $IAM_USER \
  --dry-run
```

Delete cluster:

```
./eks.py \
  -c $DEPLOYMENT \
  -A dev \
  -r $REGION \
  -a delete \
  -t cluster \
  --dry-run
```

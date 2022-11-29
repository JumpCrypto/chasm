# What is this?

We want to use the Cosmos `tx` submission endpoint,
so that only the block subscriber connects to the
Tendermint endpoint.

Fully rendering `proto.cosmos.tx.v1beta1.service.proto`
pulls in a bazillion of dependencies, therefore we use the
minified version `cosmos-tx-service.proto` in this directory.
